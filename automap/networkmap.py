#!/usr/bin/env python3

import sys
import logging
import re
from pymongo import MongoClient
import pygraphviz as pgv
from pysnmp.hlapi import *
from pprint import pprint
#from memory_profiler import profile

logger = logging.getLogger(__name__)
logger.propagate = False
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

class snmpCollector():
    def __init__(self, community, mpModel = 1):
        self.community = CommunityData(community, mpModel=mpModel)
        self.snmpEngine = SnmpEngine()

    def snmpwalk(self, host, oid):
        result = []
        for (errorIndication,
                errorStatus,
                errorIndex,
                varBinds) in nextCmd(self.snmpEngine,
                                     self.community,
                                     UdpTransportTarget((host, 161), timeout=1.0, retries=1),
                                     ContextData(),
                                     ObjectType(ObjectIdentity(oid)),
                                     lexicographicMode=False):

            if errorIndication:
                logger.error(errorIndication)
                break
            elif errorStatus:
                logger.error('%s at %s' % (errorStatus.prettyPrint(),
                                           errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for varBind in varBinds:
                    result.append(varBind)
        return result

    def snmpget(self, host, oid):
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(self.snmpEngine,
                   self.community,
                   UdpTransportTarget((host, 161), timeout=1.0, retries=1),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)),
                   lexicographicMode=False)
        )

        if errorIndication:
            logger.error(errorIndication)
        elif errorStatus:
            logger.error('%s at %s' % (errorStatus.prettyPrint(),
                                       errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            return varBinds

    def snmpset(self, host, oid, valtype, value):
        if valtype == 'i':
            value = Integer(value)
        elif valtype == 'x':
            value = OctetString(hexValue=value)
        errorIndication, errorStatus, errorIndex, varBinds = next(
            setCmd(self.snmpEngine,
                   self.community,
                   UdpTransportTarget((host, 161), timeout=1.0, retries=1),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid), value),
                   lexicographicMode=False)
        )

        if errorIndication:
            logger.error(errorIndication)
        elif errorStatus:
            logger.error('%s at %s' % (errorStatus.prettyPrint(),
                                       errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            return varBinds

class networkMap:
    def __init__(self, community = '', unreachable = []):
        client = MongoClient()
        db = client.switches_map
        relationship_db = db.relationship
        self.unreachable = unreachable
        self.networkGraph = None
        self.parents = list(relationship_db.aggregate([ { '$match': { '_id': { '$nin': relationship_db.distinct('childs._id') }}},
                                                        { '$project': { '_id' : 1, 'uplink': 1, 'swmodel': 1, 'swrev': 1, 'last_modified': 1, 'ptype': 1, 'pspeed': 1 }}
                                                      ]))
        self.relationship = list(relationship_db.find({}))
        client.close()
        self.collector = snmpCollector(community, 0)

    def __del__(self):
        pass

    def is_int(self, s):
        try:
            int(s)
            return True
        except (ValueError, TypeError):
            return False

    def getPortsId(self, host, port):
        portsName = {}
        name_raw = self.collector.snmpwalk(host, '.1.3.6.1.2.1.31.1.1.1.1')
        for result in name_raw:
            data, payload = result
            port = str(data).split('.')[-1]
            portsName[str(payload).replace('.', '_')] = int(port)

        return portsName

    def getLink(self, host, port):
        if not self.is_int(port):
            ids = self.getPortsId(host, port)
            if port_id := ids.get(port, False):
                port = port_id
            else:
                return 'неизвестно'

        results = self.collector.snmpget(host, f'1.3.6.1.2.1.2.2.1.8.{port}')
        if results is not None and len(results):
            for result in results:
                return 'Up' if result[1] == 1 else 'Down'
        return 'неизвестно'

    def getColor(self, host):
        if host in self.unreachable:
            return 'crimson'
        if 'dgs-' in host:
            return 'cyan1'
        if 'mt-' in host:
            return 'chartreuse2'
        return 'goldenrod2'

    def getSpeed(self, speed):
        if speed == 10000000:
            return '10 Mbit/s'
        elif speed == 100000000:
            return '100 Mbit/s'
        elif speed == 1000000000:
            return '1 Gbit/s'
        elif speed == 10000 or speed == 4294967295:
            return '10 Gbit/s'
        else:
            return speed

    def getLinks(self, host):
        try:
            results = self.collector.snmpwalk(host, '1.3.6.1.2.1.2.2.1.8')
            links = {}
            if results is not None and len(results):
                for result in results:
                    port, status = result
                    port = re.sub(r'1.3.6.1.2.1.2.2.1.8.', '', str(port))
                    links[port] = 'Up' if status == 1 else 'Down'
            return links
        except Exception as e:
            logger.warning(f'Ошибка: getLinks: {e}')

    def getHierarchy(self, root):
        if (len(self.relationship) > 0):
            for host in self.relationship:
                if (host['_id'] == root['_id']):
                    swtype = root['swmodel'] if root['swmodel'] in ['DES-3526', 'DGS-3100-24TG'] else '%s%s' % (root['swmodel'], root['swrev'])
                    host_label = "%s%s(%s)\n%s\n%s" % (root['uplink'], root['ptype'].get(root['uplink'], ''), self.getSpeed(root['pspeed'].get(root['uplink'], '')), root['_id'], swtype)
                    self.networkGraph.add_node(root['_id'], label=host_label, style='filled', shape='box', color=self.getColor(root['_id']))
                    family = []
                    for child in host['childs']:
                        tree = self.getHierarchy(child)
                        if (tree is not False):
                            child['childs'] = tree
                            self.networkGraph.add_edge(root['_id'], child['_id'], label='%s%s(%s)' % (child['port'], root['ptype'].get(child['port'], ''), self.getSpeed(root['pspeed'].get(child['port'], ''))), color=self.getColor(root['_id']))
                            family.append(child)
                        else:
                            swtype = child['swmodel'] if child['swmodel'] in ['DES-3526', 'DGS-3100-24TG'] else '%s%s' % (child['swmodel'], child['swrev'])
                            child_label = "%s%s(%s)\n%s\n%s" % (child['uplink'], child['ptype'].get(child['uplink'], ''), self.getSpeed(child['pspeed'].get(child['uplink'], '')), child['_id'], swtype)
                            self.networkGraph.add_node(child['_id'], label=child_label, style='filled', shape='box', color=self.getColor(child['_id']))
                            self.networkGraph.add_edge(root['_id'], child['_id'], label='%s%s(%s)' % (child['port'], root['ptype'].get(child['port'], ''), self.getSpeed(root['pspeed'].get(child['port'], ''))), color=self.getColor(root['_id']))
                            family.append(child)
                    return family
        else:
            return False
        return False

    def getPath(self, host, append = False, link = False):
        if (len(self.relationship) > 0):
            family = []
            for parent in self.relationship:
                for child in parent['childs']:
                    if (child['_id'] == host):
                        utype = parent['ptype'].get(parent['uplink'], '')
                        dtype = parent['ptype'].get(child['port'], '')
                        if link:
                            downlink = self.getLink(parent['_id'], child['port'])
                            family.append("%s%s:%s:%s%s(%s)" % (parent['uplink'], utype, parent['_id'], child['port'], dtype, downlink))
                        else:
                            family.append("%s%s:%s:%s%s" % (parent['uplink'], utype, parent['_id'], child['port'], dtype))
                        if append is True:
                            dtype = child['ptype'].get(child['uplink'], '')
                            family.append("%s%s:%s" % (child['uplink'], dtype, child['_id']))
                        result = self.getPath(parent['_id'], link = link)
                        if result is not False:
                            family = result + family
                        return family
        else:
            return False
        return False

    def saveVlanMap(self, vlan, name = "map.png", link = False):
        self.networkGraph = pgv.AGraph(directed=True, rankdir='LR')
        if (len(self.relationship) > 0 and vlan > 0 and vlan < 4096):
            for parent in self.relationship:
                vlan = str(vlan)
                if re.match(r'^mt-.+', parent['_id'], flags=re.IGNORECASE) is not None:
                    parent['vlans']['member'][vlan] = ['все']
                if not parent['vlans']['member'].get(vlan, False):
                    continue
                untag_ports = parent['vlans']['untag'].get(vlan, ['нет'])
                tag_ports = list(set(parent['vlans']['member'][vlan]) - set(untag_ports))
                if link:
                    links = self.getLinks(parent['_id'])
                    for i, port in enumerate(untag_ports):
                        if port in links:
                            untag_ports[i] = f'{port}({links[port]})'
                    for i, port in enumerate(tag_ports):
                        if port in links:
                            tag_ports[i] = f'{port}({links[port]})'
                swtype = parent['swmodel'] if parent['swmodel'] in ['DES-3526', 'DGS-3100-24TG'] else '%s%s' % (parent['swmodel'], parent['swrev'])
                host_label = "%s%s(%s)\n%s\n%s\nvlan %s\ntag: %s\nuntag: %s" % (parent['uplink'], parent['ptype'].get(parent['uplink'], ''), self.getSpeed(parent['pspeed'].get(parent['uplink'], '')), parent['_id'], swtype, vlan, ','.join(tag_ports), ','.join(untag_ports))
                self.networkGraph.add_node(parent['_id'], label=host_label, style='filled', shape='box', color=self.getColor(parent['_id']))
                for child in parent['childs']:
                    if re.match(r'^mt-.+', child['_id'], flags=re.IGNORECASE) is not None:
                        child['vlans']['member'][vlan] = ['все']
                    if not child['vlans']['member'].get(vlan, False):
                        continue
                    untag_ports = child['vlans']['untag'].get(vlan, ['нет'])
                    tag_ports = list(set(child['vlans']['member'][vlan]) - set(untag_ports))
                    if link:
                        links = self.getLinks(child['_id'])
                        for i, port in enumerate(untag_ports):
                            if port in links:
                                untag_ports[i] = f'{port}({links[port]})'
                        for i, port in enumerate(tag_ports):
                            if port in links:
                                tag_ports[i] = f'{port}({links[port]})'
                    swtype = child['swmodel'] if child['swmodel'] in ['DES-3526', 'DGS-3100-24TG'] else '%s%s' % (child['swmodel'], child['swrev'])
                    child_label = "%s%s(%s)\n%s\n%s\nvlan %s\ntag: %s\nuntag: %s" % (child['uplink'], child['ptype'].get(child['uplink'], ''), self.getSpeed(child['pspeed'].get(child['uplink'], '')), child['_id'], swtype, vlan, ','.join(tag_ports), ','.join(untag_ports))
                    self.networkGraph.add_node(child['_id'], label=child_label, style='filled', shape='box', color=self.getColor(child['_id']))
                    self.networkGraph.add_edge(parent['_id'], child['_id'], label='%s%s(%s)' % (child['port'], parent['ptype'].get(child['port'], ''), self.getSpeed(parent['pspeed'].get(child['port'], ''))), color=self.getColor(parent['_id']))
            self.networkGraph.layout(prog='dot')
            self.networkGraph.draw(name, format='png')
        self.networkGraph.clear()

    def saveMap(self, root, name = "map.png"):
        self.networkGraph = pgv.AGraph(directed=True, rankdir='LR')
        if self.getHierarchy(root) is not False:
            self.networkGraph.layout(prog='dot')
            self.networkGraph.draw(name, format='png')
        self.networkGraph.clear()

#@profile
def main():
    nm = networkMap()
    if len(sys.argv) == 2 and sys.argv[1] in ('-i', '--inventory'):
        import pymysql
        mysqlconn = pymysql.connect(charset='utf8', host='localhost', unix_socket = '/var/run/mysqld/mysqld.sock', user = 'zabbix', passwd = '', database = 'zabbix', autocommit=True)
        cursor = mysqlconn.cursor(pymysql.cursors.DictCursor)

        def mysql_do(sqlquery):
            try:
                cursor.execute(sqlquery)
            except:
                return False
            return cursor.fetchall()

        hosts = mysql_do('SELECT hostid, REPLACE(hosts.host, ".kit.ru", "") AS host FROM host_inventory LEFT JOIN hosts USING(hostid) WHERE host_inventory.type REGEXP "D[EG]S-[0-9]{4}-?[0-9]{0,2}(XS?)?"')
        for host in hosts:
            path_raw = nm.getPath(host['host'], True, False)
            if path_raw is not False and len(path_raw):
                path = ' => '.join(path_raw)
                mysql_do(f'UPDATE host_inventory SET location = "{path}" WHERE hostid = {host["hostid"]};')
        return
    if len(sys.argv) > 2 and sys.argv[1] in ('-p', '--path'):
        path_raw = nm.getPath(sys.argv[2].replace('.kit.ru', ''), True, False)
        if path_raw is not False and len(path_raw):
            print(' => '.join(path_raw))
        else:
            print('неизвестно')
        return

    #nm.saveMap(nm.parents[11])
    path = nm.getPath('des-pka9bp8', link = True)
    pprint(path)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print()