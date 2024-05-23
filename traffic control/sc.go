package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// конфиг
var cfg Config

// Config конфиг
type Config struct {
	Init  bool
	Mutex sync.Mutex
	MySQL struct {
		User string `json:"User"`
		Pass string `json:"Pass"`
		DB   string `json:"DB"`
		Addr string `json:"Addr"`
	} `json:"MySQL"`
	Shaper struct {
		RateRatio      float32  `json:"RateRatio"`
		BlockedSpeed   uint32   `json:"BlockedSpeed"`
		Holidays       []string `json:"Holidays"`
		FilterNetworks []string `json:"FilterNetworks"`
		BypassNetworks []string `json:"BypassNetworks"`
		DefaultPolicy  string   `json:"DefaultPolicy"`
		Interface      string   `json:"Interface"`
	} `json:"Shaper"`
	Mirror struct {
		Enable    bool   `json:"Enable"`
		Interface string `json:"Interface"`
	} `json:"Mirror"`
}

type tcShaper struct {
	connector      *sql.DB
	tc             string
	prefMirror     uint32
	prefBypass     uint32
	prefHash       uint32
	prefLeaf       uint32
	prefDefault    uint32
	classDefault   uint32
	iface          string
	filterNetworks map[string]netData
}

type netData struct {
	ht       uint32
	ip       net.IP
	netmask  uint32
	leafht_i uint32
}

type filterData struct {
	ip map[string]string
}

type userData struct {
	shape uint32
	ip    []string
}

func init() {
	initPtr := flag.Bool("init", false, "init hash tables")
	confPtr := flag.String("c", "/etc/sc.conf.json", "a string")
	flag.Parse()

	confFile, err := os.Open(*confPtr)
	if err != nil {
		log.Fatalf("[init] Не удалось открыть файл с настройками: %s\n", err)
	}
	defer confFile.Close()

	decoder := json.NewDecoder(confFile)
	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatalf("[init] Не удалось прочитать настройки из файла: %s\n", err)
	}

	cfg.Init = *initPtr
}

func IP2Long(ip net.IP) uint32 {
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip)
}

func Long2IP(ipLong, netmaskLong uint32) (net.IP, *net.IPNet, uint32) {
	ipByte := make([]byte, 4)
	netmaskByte := make([]byte, 4)

	binary.BigEndian.PutUint32(ipByte, ipLong)
	ip := net.IP(ipByte)

	binary.BigEndian.PutUint32(netmaskByte, netmaskLong)
	netmask := net.IPMask(netmaskByte)
	size, _ := netmask.Size()

	return ip, &net.IPNet{IP: ip.Mask(netmask), Mask: netmask}, uint32(size)
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func inArray(lookup string, list []string) bool {
	for _, val := range list {
		if val == lookup {
			return true
		}
	}
	return false
}

// 10.70.128.249/32 => 0a4680f9/ffffffff
func hexCIDR(cidr string) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}
	ip = ip.Mask(ipnet.Mask)
	hexIP := hex.EncodeToString([]byte(ip))
	hexMask := ipnet.Mask.String()
	return hexIP + "/" + hexMask, nil
}

// 0a4680f9/ffffffff => 10.70.128.249/32
func asciiCIDR(cidr string) (string, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "", fmt.Errorf("[asciiCIDR] неправильный формат CIDR: %s", cidr)
	}
	ipData, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	ip := net.IP(ipData)

	maskData, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	mask := net.IPMask(maskData)
	size, _ := mask.Size()

	return fmt.Sprintf("%s/%d", ip.String(), size), nil
}

// экспонента a**n
func power(a, n uint32) uint32 {
	var result uint32 = 1
	for i := uint32(0); i < n; i++ {
		result *= a
	}
	return result
}

func u32_div_hmask(netmask, oct uint32) (uint32, string) {
	inthmask := (power(2, 32-netmask) - 1) & (0xFF << uint(8*(4-oct)))
	div := (inthmask >> uint(8*(4-oct))) + 1
	return div, fmt.Sprintf("0x%08x", inthmask)
}

// создать tcShaper для интерфейса
func NewTCShaper(iface string) *tcShaper {
	mysqlconn, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", cfg.MySQL.User, cfg.MySQL.Pass, cfg.MySQL.Addr, cfg.MySQL.DB))
	if err != nil {
		log.Fatalf("[init] Не удалось подключиться к mysql: %s\n", err)
	}

	mysqlconn.SetMaxOpenConns(50)
	mysqlconn.SetConnMaxLifetime(time.Hour)

	path, err := exec.LookPath("tc")
	if err != nil {
		log.Fatalf("[init] Не удалось обнаружить tc: %s", err)
	}

	fn, err := getFilterNetworks(cfg.Shaper.FilterNetworks)
	if err != nil {
		log.Fatalf("Не удалось инициализировать сети шейпера: %s", err)
	}

	shaper := &tcShaper{
		connector:      mysqlconn,
		tc:             path,
		prefMirror:     4,  // зеркалирование
		prefBypass:     5,  // разрешенные сети
		prefHash:       10, // хэш фильтры
		prefLeaf:       20, // вложенные фильтры
		prefDefault:    30, // дефолтное правило
		classDefault:   0xfffe,
		iface:          iface,
		filterNetworks: fn,
	}

	return shaper
}

func (t *tcShaper) exec(args ...string) error {
	cmd := exec.Command(t.tc, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Ошибка при выполнении: %s %s \n", t.tc, strings.Join(args, " "))
		log.Printf("Вывод tc: %s \n", string(out))
	}

	return err
}

func (t *tcShaper) resetInterface() error {
	return t.exec("qdisc", "del", "dev", t.iface, "root")
}

func (t *tcShaper) initializeInterface() error {
	return t.exec("qdisc", "add", "dev", t.iface, "root", "handle", "1:", "htb", "default", fmt.Sprintf("%x", t.classDefault))
}

func (t *tcShaper) init() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, i := range ifaces {
		if i.Name == t.iface {
			addrs, err := i.Addrs()
			if err != nil {
				return err
			}
			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					cfg.Shaper.BypassNetworks = append(cfg.Shaper.BypassNetworks, fmt.Sprintf("%s/32", v.IP.String()))
				}
			}
		}
	}

	if err := t.resetInterface(); err != nil {
		log.Printf("warning: не удалось сбросить интерфейс: %v \n", err)
	}

	if err := t.exec("qdisc", "del", "dev", t.iface, "ingress"); err != nil {
		log.Printf("warning[mirror]: не удалось сбросить интерфейс: %v \n", err)
	}

	if err := t.initializeInterface(); err != nil {
		return err
	}

	if cfg.Mirror.Enable {
		if err := t.exec("qdisc", "add", "dev", t.iface, "handle", "ffff:", "ingress"); err != nil {
			log.Printf("warning[mirror]: не удалось добавить дисциплину очередности: %v \n", err)
		}

		if err := t.initMirror(); err != nil {
			log.Printf("warning[mirror]: не удалось добавить фильтр: %v \n", err)
		}
	}

	if err := t.initFilterNetworks(); err != nil {
		return err
	}

	if err := t.initBypass(cfg.Shaper.BypassNetworks); err != nil {
		return err
	}

	if err := t.initDefault("pass"); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) initMirror() error {
	if err := t.exec("filter", "add",
		"dev", t.iface,
		"parent", "ffff:",
		"pref", "49152",
		"protocol", "all",
		"u32", "match", "u32", "0", "0",
		"action", "mirred", "egress", "mirror", "dev", cfg.Mirror.Interface); err != nil {
		return err
	}
	if err := t.exec("filter", "add",
		"dev", t.iface,
		"parent", "1:",
		"pref", fmt.Sprintf("%d", t.prefMirror),
		"protocol", "all",
		"u32", "match", "u32", "0", "0",
		"action", "mirred", "egress", "mirror", "dev", cfg.Mirror.Interface, "continue"); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) initBypass(ips []string) error {
	for _, ip := range ips {
		if err := t.addFilter(t.prefBypass, ip); err != nil {
			log.Printf("[initBypass] Не удалось добавить фильтр: %s\n", err)
		}
	}

	if err := t.exec("filter", "add",
		"dev", t.iface,
		"parent", "1:0",
		"pref", fmt.Sprintf("%d", t.prefBypass),
		"protocol", "ip", "u32",
		//      "match", "ip", "protocol", "6", "0xff",
		//      "match", "ip", "sport", "80", "0xffff",
		"match", "mark", "0x1", "0xffff",
		"action", "pass"); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) initFilterNetworks() error {
	offset := 16

	if err := t.exec("filter", "add",
		"dev", t.iface,
		"parent", "1:0",
		"pref", fmt.Sprintf("%d", t.prefHash),
		"protocol", "ip", "u32"); err != nil {
		return err
	}

	for network, data := range t.filterNetworks {
		if data.netmask >= 24 && data.netmask < 31 {
			div1, hmask1 := u32_div_hmask(data.netmask, 4)

			if err := t.exec("filter", "add",
				"dev", t.iface,
				"parent", "1:0",
				"pref", fmt.Sprintf("%d", t.prefHash),
				"protocol", "ip",
				"handle", fmt.Sprintf("%x:", data.ht),
				"u32",
				"divisor", fmt.Sprintf("%d", div1)); err != nil {
				return err
			}

			if err := t.exec("filter", "add",
				"dev", t.iface,
				"parent", "1:0",
				"pref", fmt.Sprintf("%d", t.prefHash),
				"protocol", "ip",
				"u32", "ht", "800::",
				"match", "ip", "dst", fmt.Sprintf("%s", network),
				"hashkey", "mask", fmt.Sprintf("%s", hmask1), "at", fmt.Sprintf("%d", offset),
				"link", fmt.Sprintf("%x:", data.ht)); err != nil {
				return err
			}
		} else if data.netmask >= 16 && data.netmask < 24 {
			div1, hmask1 := u32_div_hmask(data.netmask, 3)

			if err := t.exec("filter", "add",
				"dev", t.iface,
				"parent", "1:0",
				"pref", fmt.Sprintf("%d", t.prefHash),
				"protocol", "ip",
				"handle", fmt.Sprintf("%x:", data.ht),
				"u32",
				"divisor", fmt.Sprintf("%d", div1)); err != nil {
				return err
			}

			if err := t.exec("filter", "add",
				"dev", t.iface,
				"parent", "1:0",
				"pref", fmt.Sprintf("%d", t.prefHash),
				"protocol", "ip",
				"u32", "ht", "800::",
				"match", "ip", "dst", fmt.Sprintf("%s", network),
				"hashkey", "mask", fmt.Sprintf("%s", hmask1), "at", fmt.Sprintf("%d", offset),
				"link", fmt.Sprintf("%x:", data.ht)); err != nil {
				return err
			}

			div2, hmask2 := u32_div_hmask(data.netmask, 4)

			for i := uint32(0); i < div1; i++ {
				if err := t.exec("filter", "add",
					"dev", t.iface,
					"parent", "1:0",
					"pref", fmt.Sprintf("%d", t.prefHash),
					"protocol", "ip",
					"handle", fmt.Sprintf("%x:", data.leafht_i+i),
					"u32",
					"divisor", fmt.Sprintf("%d", div2)); err != nil {
					return err
				}

				network2 := fmt.Sprintf("%d.%d.%d.%d/24", data.ip[0], data.ip[1], uint32(data.ip[2])+i, data.ip[3])

				if err := t.exec("filter", "add",
					"dev", t.iface,
					"parent", "1:0",
					"pref", fmt.Sprintf("%d", t.prefHash),
					"protocol", "ip",
					"u32", "ht", fmt.Sprintf("%x:%x:", data.ht, i),
					"match", "ip", "dst", fmt.Sprintf("%s", network2),
					"hashkey", "mask", fmt.Sprintf("%s", hmask2), "at", fmt.Sprintf("%d", offset),
					"link", fmt.Sprintf("%x:", data.leafht_i+i)); err != nil {
					return err
				}
			}
		} else {
			log.Printf("Неподдерживаемая сеть: %v\n", network)
			continue
		}
	}

	return nil
}

func (t *tcShaper) initDefault(policy string) error {
	if policy == "pass" {
		if !cfg.Init {
			t.exec("filter", "del",
				"dev", t.iface,
				"parent", "1:0",
				"pref", fmt.Sprintf("%d", t.prefDefault),
				"protocol", "ip", "u32",
				"match", "u32", "0", "0", "at", "0",
				"action", "drop")
		}
		if err := t.addClass(t.classDefault, 10*1024*1024); err != nil {
			return err
		}
	} else {
		if !cfg.Init {
			t.delClass(t.classDefault)
		}
		if err := t.exec("filter", "add",
			"dev", t.iface,
			"parent", "1:0",
			"pref", fmt.Sprintf("%d", t.prefDefault),
			"protocol", "ip", "u32",
			"match", "u32", "0", "0", "at", "0",
			"action", "drop"); err != nil {
			return err
		}
	}

	return nil
}

func (t *tcShaper) sync() error {
	users, err := t.getUsers()
	if err != nil {
		log.Printf("[main] Не удалось получить пользователей из биллинга: %s\n", err)
		return err
	}

	socResources, err := t.getSocResources()
	if err != nil {
		log.Printf("[main] Не удалось получить список социально значимых ресурсов из биллинга: %s\n", err)
		return err
	}

	curClasses, err := t.getClasses()
	if err != nil {
		log.Printf("[sync] Не удалось получить список текущих классов: %s\n", err)
		return err
	}

	curFilters, bypassFilters, err := t.getFilters()
	if err != nil {
		log.Printf("[sync] Не удалось получить список текущих фильтов: %s\n", err)
		return err
	}

	// обход по фильтрам в tc
	for uid, data := range curFilters {
		// если текущий фильтр есть в базе биллинга
		if user, ok := users[uid]; ok {
			// если фильтры абонента существует в базе биллинга
			// необходимо сверить айпишники и удалить лишние
			for ip, handle := range data.ip {
				if !inArray(ip, user.ip) {
					if err := t.delFilter(t.prefLeaf, handle); err != nil {
						log.Printf("[sync] Не удалось удалить фильтр: %s\n", err)
					}
				}
			}
			// если текущего фильтра нет в базе биллинга
			// удаляем все фильтры пользователя
		} else {
			for _, handle := range data.ip {
				if err := t.delFilter(t.prefLeaf, handle); err != nil {
					log.Printf("[sync] Не удалось удалить фильтр: %s\n", err)
				}
			}
		}
	}

	// обход по классам в tc
	for uid, _ := range curClasses {
		// если текущего класса нет в базе биллинга, то удаляем его
		if _, ok := users[uid]; !ok {
			if err := t.delClass(uid); err != nil {
				log.Printf("[sync] Не удалось удалить класс: %s\n", err)
			}
		}
	}

	// обход по абонентам
	for uid, data := range users {
		// если класс абонента существует в tc
		if curShape, ok := curClasses[uid]; ok {
			// проверяем скорость
			if curShape != data.shape {
				if err := t.changeClass(uid, data.shape); err != nil {
					log.Printf("[sync] Не удалось изменить класс: %s\n", err)
					continue
				}
			}

			// если фильтры абонента существует в tc
			// необходимо сверить айпишники и добавить недостающие
			if curFilter, ok := curFilters[uid]; ok {
				for i := 0; i < len(data.ip); i++ {
					if _, ok := curFilter.ip[data.ip[i]]; !ok {
						if err := t.addClassFilter(t.prefLeaf, uid, data.ip[i]); err != nil {
							log.Printf("[sync] Не удалось добавить фильтр: %s\n", err)
						}
					}
				}
				// иначе добавляем все фильтры
			} else {
				for i := 0; i < len(data.ip); i++ {
					if err := t.addClassFilter(t.prefLeaf, uid, data.ip[i]); err != nil {
						log.Printf("[sync] Не удалось добавить фильтр: %s\n", err)
					}
				}
			}
			// если класс абонента не существует в tc то добавляем класс и все фильтры
		} else {
			if err := t.addClass(uid, data.shape); err != nil {
				log.Printf("[sync] Не удалось добавить класс: %s\n", err)
				continue
			}
			for i := 0; i < len(data.ip); i++ {
				if err := t.addClassFilter(t.prefLeaf, uid, data.ip[i]); err != nil {
					log.Printf("[sync] Не удалось добавить фильтр: %s\n", err)
				}
			}
		}
	}

	// обход по СЗР в tc
	for network, handles := range bypassFilters {
		// если текущего фильтра нет в базе биллинга
		// удаляем его из tc
		if _, ok := socResources[network]; !ok {
			for _, handle := range handles {
				if err := t.delFilter(t.prefBypass, handle); err != nil {
					log.Printf("[sync] Не удалось удалить фильтр (socResources): %s\n", err)
				}
			}
		}
	}

	// обход по СЗР в биллинге
	for network, _ := range socResources {
		// если текущего фильтра нет в tc
		// добавляем его
		if _, ok := bypassFilters[network]; !ok {
			if err := t.addFilter(t.prefBypass, network); err != nil {
				log.Printf("[sync] Не удалось добавить фильтр (socResources): %s\n", err)
			}
		}
	}

	return nil
}

func (t *tcShaper) nextClassID() (uint32, error) {
	data, err := exec.Command(t.tc, "class", "show", "dev", t.iface).CombinedOutput()
	if err != nil {
		return 0, err
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	classes := make(map[string]bool, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// пропускаем пустые строки
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, " ")
		// должно быть:
		// class htb 1:25da root leaf 25da: prio 0 rate 307200Kbit ceil 307200Kbit burst 1536b cburst 1536b
		if len(parts) != 16 {
			return 0, fmt.Errorf("[nextClassID] неожиданный ответ от tc: %d (%v)", len(parts), parts)
		}
		classes[parts[2]] = true
	}

	for nextClass := uint32(1); nextClass < 0xffff; nextClass++ {
		_, contained := classes[fmt.Sprintf("1:%d", nextClass)]
		if !contained {
			return nextClass, nil
		}
	}

	return 0, fmt.Errorf("[nextClassID] закончились классы")
}

func (t *tcShaper) addClass(classID, rate uint32) error {
	if classID > 0xffff {
		return fmt.Errorf("[addClass] Превышен лимит классов: %d", classID)
	}

	if err := t.exec("class", "replace",
		"dev", t.iface,
		"parent", "1:",
		"classid", fmt.Sprintf("1:%x", classID),
		"htb",
		"rate", fmt.Sprintf("%dKbit", rate),
		"quantum", "200000"); err != nil {
		return err
	}

	if err := t.exec("qdisc", "replace",
		"dev", t.iface,
		"parent", fmt.Sprintf("1:%x", classID),
		"handle", fmt.Sprintf("%x:0", classID),
		//"sfq", "perturb", "10"); err != nil {
		"pfifo", "limit", "100"); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) changeClass(classID, rate uint32) error {
	if classID > 0xffff {
		return fmt.Errorf("[changeClass] Превышен лимит классов: %d", classID)
	}

	if err := t.exec("class", "replace",
		"dev", t.iface,
		"parent", "1:",
		"classid", fmt.Sprintf("1:%x", classID),
		"htb",
		"rate", fmt.Sprintf("%dKbit", rate),
		"quantum", "200000"); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) delClass(classID uint32) error {
	if classID > 0xffff {
		return fmt.Errorf("[delClass] Превышен лимит классов: %d", classID)
	}

	if err := t.exec("qdisc", "del",
		"dev", t.iface,
		"parent", fmt.Sprintf("1:%x", classID),
		"handle", fmt.Sprintf("%x:0", classID)); err != nil {
		return err
	}

	if err := t.exec("class", "del",
		"dev", t.iface,
		"parent", "1:",
		"classid", fmt.Sprintf("1:%x", classID)); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) getClasses() (map[uint32]uint32, error) {
	classes := make(map[uint32]uint32)

	data, err := exec.Command(t.tc, "class", "show", "dev", t.iface).CombinedOutput()
	if err != nil {
		return classes, err
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// пропускаем пустые строки
		if len(line) == 0 {
			continue
		}
		parts := strings.Split(line, " ")
		// должно быть:
		// class htb 1:25da root leaf 25da: prio 0 rate 307200Kbit ceil 307200Kbit burst 1536b cburst 1536b
		if len(parts) != 16 {
			return classes, fmt.Errorf("[getClasses] Неожиданный ответ от tc: %d (%v)", len(parts), parts)
		}
		classid_parts := strings.Split(parts[2], ":")
		if len(classid_parts) != 2 {
			continue
		}
		classid, err := strconv.ParseUint(classid_parts[1], 16, 32)
		if err != nil {
			continue
		}

		// пропускаем дефолтный класс из выдачи, чтобы его не удалил синкер
		if uint32(classid) == t.classDefault {
			continue
		}

		var shape uint32 = 0
		if strings.Contains(parts[9], "Kbit") {
			u64, err := strconv.ParseUint(parts[9][:len(parts[9])-4], 10, 32)
			if err != nil {
				continue
			}
			shape = uint32(u64)
		} else if strings.Contains(parts[9], "Mbit") {
			u64, err := strconv.ParseUint(parts[9][:len(parts[9])-4], 10, 32)
			if err != nil {
				continue
			}
			shape = uint32(u64 * 1024)
		} else if strings.Contains(parts[9], "Gbit") {
			u64, err := strconv.ParseUint(parts[9][:len(parts[9])-4], 10, 32)
			if err != nil {
				continue
			}
			shape = uint32(u64 * 1024 * 1024)
		}

		classes[uint32(classid)] = shape
	}

	return classes, nil
}

func (t *tcShaper) addClassFilter(pref uint32, classID uint32, cidr string) error {
	if classID > 0xffff {
		return fmt.Errorf("[addClassFilter] Превышен лимит классов: %d", classID)
	}

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("[addClassFilter] Не удалось спарсить CIDR: %v\n", err)
	}

	// хеши /24 сетей - листьев fn
	var ht uint32 = 0
	// ht:key последний октет сети которая матчится
	key := ipnet.IP[3]

	for network, data := range t.filterNetworks {
		_, n, err := net.ParseCIDR(network)
		if err != nil {
			return fmt.Errorf("[addClassFilter] Не удалось спарсить CIDR: %v\n", err)
		}

		if n.Contains(ip) {
			if data.netmask >= 24 && data.netmask < 31 {
				ht = data.leafht_i
			} else if data.netmask >= 16 && data.netmask < 24 {
				ht = data.leafht_i + uint32(ipnet.IP[2]-n.IP[2])
			} else {
				log.Printf("[addClassFilter] Неподдерживаемая сеть: %v\n", network)
			}
		}
	}

	if ht < 1 {
		return fmt.Errorf("[addClassFilter] Не найдено хэш таблицы для: %s\n", cidr)
	}

	if err := t.exec("filter", "replace",
		"dev", t.iface,
		"parent", "1:",
		"pref", fmt.Sprintf("%d", pref),
		"protocol", "ip",
		"handle", fmt.Sprintf("%x:%x:800", ht, key), "u32",
		"ht", fmt.Sprintf("%x:%x:", ht, key),
		"match", "ip", "dst", cidr,
		"flowid", fmt.Sprintf("1:%x", classID)); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) addFilter(pref uint32, cidr string) error {
	if err := t.exec("filter", "add",
		"dev", t.iface,
		"parent", "1:0",
		"pref", fmt.Sprintf("%d", pref),
		"protocol", "ip", "u32",
		"match", "ip", "src", cidr,
		"action", "pass"); err != nil {
		return err
	}
	if err := t.exec("filter", "add",
		"dev", t.iface,
		"parent", "1:0",
		"pref", fmt.Sprintf("%d", pref),
		"protocol", "ip", "u32",
		"match", "ip", "dst", cidr,
		"action", "pass"); err != nil {
		return err
	}
	return nil
}

func (t *tcShaper) delFilter(pref uint32, handle string) error {
	if err := t.exec("filter", "del",
		"dev", t.iface,
		"parent", "1:",
		"pref", fmt.Sprintf("%d", pref),
		"protocol", "ip",
		"handle", handle, "u32"); err != nil {
		return err
	}

	return nil
}

func (t *tcShaper) getFilters() (map[uint32]filterData, map[string][]string, error) {
	classFilters := make(map[uint32]filterData)
	bypassFilters := make(map[string][]string)

	data, err := exec.Command(t.tc, "filter", "show", "dev", t.iface).CombinedOutput()
	if err != nil {
		return classFilters, bypassFilters, err
	}

	scanner := bufio.NewScanner(bytes.NewBuffer(data))
	filter := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}
		if strings.HasPrefix(line, "filter") {
			filter = line
			continue
		}
		if strings.Contains(line, "match") {
			if !strings.Contains(filter, "flowid 1:") && !strings.Contains(filter, "flowid ???") {
				continue
			}

			cidr_parts := strings.Split(line, " ")
			if len(cidr_parts) != 4 {
				return classFilters, bypassFilters, fmt.Errorf("[getFilters] Неожиданный ответ от tc (match): %d, %v", len(cidr_parts), cidr_parts)
			}
			cidr, err := asciiCIDR(cidr_parts[1])
			if err != nil {
				return classFilters, bypassFilters, err
			}

			filter_parts := strings.Split(filter, " ")

			if strings.Contains(filter, fmt.Sprintf("pref %d", t.prefHash)) {
				// должно быть:
				// filter parent 1: protocol ip pref 10 u32 chain 0 fh 401:82:800 order 2048 key ht 401 bkt 82 flowid 1:25da not_in_hw
				if len(filter_parts) != 22 {
					return classFilters, bypassFilters, fmt.Errorf("[getFilters] Неожиданный ответ от tc (filter): %d (%v)", len(filter_parts), filter_parts)
				}

				flowid_parts := strings.Split(filter_parts[20], ":")
				if len(flowid_parts) != 2 {
					continue
				}
				u64, err := strconv.ParseUint(flowid_parts[1], 16, 32)
				if err != nil {
					continue
				}
				flowid := uint32(u64)

				if val, ok := classFilters[flowid]; ok {
					val.ip[cidr] = filter_parts[11]
					classFilters[flowid] = val
				} else {
					classFilters[flowid] = filterData{
						ip: map[string]string{
							cidr: filter_parts[11],
						},
					}
				}
			}

			if strings.Contains(filter, fmt.Sprintf("pref %d", t.prefBypass)) {
				// должно быть:
				// filter parent 1: protocol ip pref 5 u32 chain 0 fh 802::81e order 2078 key ht 802 bkt 0 terminal flowid ??? not_in_hw
				if len(filter_parts) != 23 {
					return classFilters, bypassFilters, fmt.Errorf("[getFilters] Неожиданный ответ от tc (filter): %d (%v)", len(filter_parts), filter_parts)
				}

				if val, ok := bypassFilters[cidr]; ok {
					bypassFilters[cidr] = append(val, filter_parts[11])
				} else {
					bypassFilters[cidr] = []string{filter_parts[11]}
				}
			}
		}
	}

	return classFilters, bypassFilters, nil
}

func (t *tcShaper) getUsers() (map[uint32]userData, error) {
	users := make(map[uint32]userData)

	holidays := strings.Join(cfg.Shaper.Holidays, "','")
	ipRows, err := t.connector.Query(fmt.Sprintf("SELECT vg_id, segment, mask, IF(vgroups.blocked AND DATE_FORMAT(CURDATE(), '%%d-%%m') NOT IN ('%s'), %d, IF(vgroups.shape, vgroups.shape, IF(CURTIME() BETWEEN time_shape.timefrom AND time_shape.timeto, time_shape.shape_rate, tarifs.shape))) AS shape FROM staff LEFT JOIN vgroups USING(vg_id) LEFT JOIN tarifs USING(tar_id) LEFT JOIN time_shape USING(tar_id) WHERE vgroups.archive = 0 AND (vgroups.blocked = 0 OR (vgroups.blocked > 0 AND vg_id IN (SELECT vg_id FROM free_internet WHERE free_internet.mark = 0 AND free_internet.c_date >= NOW() - INTERVAL 1 HOUR)) OR DATE_FORMAT(CURDATE(), '%%d-%%m') IN ('%s')) AND tarifs.tar_id NOT IN (37, 296)", holidays, cfg.Shaper.BlockedSpeed, holidays))
	if err != nil {
		return users, fmt.Errorf("[getUsers] Не удалось выполнить sql запрос: %s", err)
	}
	defer ipRows.Close()

	for ipRows.Next() {
		var uid, ip, mask, shape uint32
		err := ipRows.Scan(&uid, &ip, &mask, &shape)
		if err != nil {
			log.Printf("[getUsers] Ошибка извлечения данных из sql ответа: %s\n", err)
			continue
		}

		ipaddr, ipnet, netmask := Long2IP(ip, mask)

		if shape == 0 {
			shape = 102400
		}
		if n := shape % 1000; n == 0 {
			shape = shape / 1000 * 1024
		}

		if netmask == 32 {
			cidr := fmt.Sprintf("%s/%d", ipaddr.String(), netmask)
			if val, ok := users[uid]; ok {
				val.ip = append(val.ip, cidr)
				users[uid] = val
			} else {
				users[uid] = userData{
					shape: uint32(float32(shape) * cfg.Shaper.RateRatio),
					ip:    []string{cidr},
				}
			}
		} else if netmask >= 16 && netmask < 32 {
			ips := make([]string, 0, 4)

			for ipaddr := ipaddr.Mask(ipnet.Mask); ipnet.Contains(ipaddr); incIP(ipaddr) {
				ips = append(ips, fmt.Sprintf("%s/%d", ipaddr.String(), 32))
			}

			if val, ok := users[uid]; ok {
				val.ip = append(val.ip, ips...)
				users[uid] = val
			} else {
				users[uid] = userData{
					shape: uint32(float32(shape) * cfg.Shaper.RateRatio),
					ip:    ips,
				}
			}
		} else {
			log.Printf("[addFilter] Неподдерживаемая сеть: %s/%d\n", ipaddr.String(), netmask)
		}
	}

	return users, nil
}

func (t *tcShaper) getSocResources() (map[string]string, error) {
	networks := make(map[string]string)
	distinctNetworks := make(map[string]string)

	ipRows, err := t.connector.Query("SELECT DISTINCT network, descr FROM social_resources")
	if err != nil {
		return networks, fmt.Errorf("[getSocResources] Не удалось выполнить sql запрос: %s", err)
	}
	defer ipRows.Close()

	for _, network := range cfg.Shaper.BypassNetworks {
		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			log.Printf("[getSocResources] Не удалось распознать сеть (%s): %s\n", network, err)
			continue
		}
		networks[ipnet.String()] = "default"
	}

	for ipRows.Next() {
		var network string
		var descr string
		err := ipRows.Scan(&network, &descr)
		if err != nil {
			log.Printf("[getSocResources] Ошибка извлечения данных из sql ответа: %s\n", err)
			continue
		}

		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			log.Printf("[getSocResources] Не удалось распознать сеть (%s): %s\n", network, err)
			continue
		}

		networks[ipnet.String()] = descr
	}

	for k1, v1 := range networks {
		overlap := false
		_, n1, _ := net.ParseCIDR(k1)
		for k2, _ := range networks {
			if k1 == k2 {
				continue
			}
			_, n2, _ := net.ParseCIDR(k2)
			if n2.Contains(n1.IP) {
				overlap = true
			}
		}
		if !overlap {
			distinctNetworks[k1] = v1
		}
	}

	return distinctNetworks, nil
}

func getFilterNetworks(fn []string) (map[string]netData, error) {
	result := make(map[string]netData)
	var ht_max uint32 = 0x7ff
	// хеши сетей из fn
	var ht1 uint32 = 0x100
	// хеши /24 сетей - листьев fn
	var ht2 uint32 = ht1 + 0x100

	for i := 0; i < len(fn); i++ {
		network := fn[i]

		_, ipnet, err := net.ParseCIDR(network)
		if err != nil {
			log.Printf("[getFilterNetworks] Не удалось спарсить CIDR: %v\n", err)
			continue
		}

		netmask, _ := ipnet.Mask.Size()
		cidr := fmt.Sprintf("%s/%d", ipnet.IP.String(), netmask)

		if netmask >= 24 && netmask < 32 {
			result[cidr] = netData{
				ht:       ht1,
				ip:       ipnet.IP,
				netmask:  uint32(netmask),
				leafht_i: ht1,
			}
		} else if netmask >= 16 && netmask < 24 {
			result[cidr] = netData{
				ht:       ht1,
				ip:       ipnet.IP,
				netmask:  uint32(netmask),
				leafht_i: ht2,
			}
			ht2 += power(2, 24-uint32(netmask))
		} else {
			log.Printf("[getFilterNetworks] Неподдерживаемая сеть: %v\n", network)
			continue
		}

		ht1++
		if ht2 > ht_max {
			return result, fmt.Errorf("[getFilterNetworks] Закончились идентификаторы хэш таблиц: %v", network)
		}
	}

	return result, nil
}

func main() {
	sc := NewTCShaper(cfg.Shaper.Interface)
	curPolicy := cfg.Shaper.DefaultPolicy

	if cfg.Init {
		log.Println("[main] Инициализация")

		if err := sc.init(); err != nil {
			log.Fatalf("[main] Не удалось инициализировать шейпер: %s\n", err)
		}

		users, err := sc.getUsers()
		if err != nil {
			log.Printf("[main] Не удалось получить пользователей из биллинга: %s\n", err)
		} else {
			for uid, data := range users {
				if err := sc.addClass(uid, data.shape); err != nil {
					log.Printf("[main] Не удалось добавить класс: %s\n", err)
					continue
				}
				for i := 0; i < len(data.ip); i++ {
					if err := sc.addClassFilter(sc.prefLeaf, uid, data.ip[i]); err != nil {
						log.Printf("[main] Не удалось добавить фильтр: %s\n", err)
					}
				}
			}
		}
		cfg.Init = false
		if curPolicy != "pass" {
			sc.initDefault(curPolicy)
		}
		log.Println("[main] Инициализация закончена")
	} else {
		log.Println("[main] Синхронизация")
		if err := sc.sync(); err != nil {
			log.Printf("[main] Не удалось синхронизировать: %s\n", err)
			if curPolicy != "pass" {
				curPolicy = "pass"
				sc.initDefault(curPolicy)
			}
		}
		log.Println("[main] Синхронизация закончена")
	}

	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for {
			sig := <-signalChannel
			cfg.Mutex.Lock()
			switch sig {
			case syscall.SIGUSR1:
				log.Println("[main] Получен сигнал USR1 = pass")
				cfg.Shaper.DefaultPolicy = "pass"
			case syscall.SIGUSR2:
				log.Println("[main] Получен сигнал USR2 = block")
				cfg.Shaper.DefaultPolicy = "block"
			}
			cfg.Mutex.Unlock()
		}
	}()

	for {
		time.Sleep(time.Minute)
		log.Println("[main] Синхронизация")
		if err := sc.sync(); err != nil {
			log.Printf("[main] Не удалось синхронизировать: %s\n", err)
			if curPolicy != "pass" {
				curPolicy = "pass"
				log.Printf("[main] Была изменена политика шейпера: %s\n", curPolicy)
				sc.initDefault(curPolicy)
			}
		} else {
			cfg.Mutex.Lock()
			if curPolicy != cfg.Shaper.DefaultPolicy {
				curPolicy = cfg.Shaper.DefaultPolicy
				log.Printf("[main] Была изменена политика шейпера: %s\n", curPolicy)
				sc.initDefault(curPolicy)
			}
			cfg.Mutex.Unlock()
		}
		log.Println("[main] Синхронизация закончена")
	}

	//sc.exec("qdisc", "show", "dev", "eth1")
	//sc.exec("class", "show", "dev", "eth1")
	//sc.exec("filter", "show", "dev", "eth1")
}
