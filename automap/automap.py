#!/usr/bin/env python3

import sys
import re
import json
import dns.query
import dns.zone
import pymysql
from pysnmp.hlapi import *
from pymongo import MongoClient
from pymongo.errors import BulkWriteError
from pymongo.errors import DuplicateKeyError
from pprint import pprint
import multiprocessing as mp
import logging
from time import strftime
from datetime import datetime, timedelta
from time import sleep
import requests
from requests.auth import HTTPDigestAuth
from rosapi import ROSApi

logger = logging.getLogger(__name__)
logger.propagate = False
logger.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

strict_relationship = 0
workers = 12
repoll_time = 1
collecting = True

management_vlan = 184
uplink_mac = "00:00:cd:2b:e5:23"
exclude_hosts = ['des-s1', 'des-s1-2', 'des-s1-3', 'des-s1-4']

switchoid = {
    'DGS-3100-24TG': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4'
    },
    'DGS-3200-10B1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.101.1.2.3.1.1.5'
    },
    'DGS-3120-24SCA1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.117.1.3.2.3.1.1.5'
    },
    'DGS-3120-24SCA2': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.117.1.3.2.3.1.1.5'
    },
    'DGS-3120-24SCB1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.117.4.1.2.3.1.1.5'
    },
    'DGS-3120-24TCA2': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.117.1.1.2.3.1.1.5'
    },
    'DES-3526': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'port_type': '1.3.6.1.4.1.171.11.64.1.2.4.1.1.3',
    },
    'DES-3200-18A1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.1.2.2.2.1.1.4'
    },
    'DES-3200-18B1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.1.2.2.2.1.1.4'
    },
    'DES-3200-18C1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.3.1.2.3.1.1.5'
    },
    'DES-3200-26A1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.1.5.2.2.1.1.4'
    },
    'DES-3200-26C1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.4.1.2.3.1.1.5'
    },
    'DES-3200-28A1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.1.3.2.2.1.1.4'
    },
    'DES-3200-28FA1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.1.4.2.2.1.1.4'
    },
    'DES-3200-28C1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.5.1.2.3.1.1.5'
    },
    'DES-3200-28FC1': {
        'member_ports': '1.3.6.1.2.1.17.7.1.4.3.1.2',
        'untag_ports': '1.3.6.1.2.1.17.7.1.4.3.1.4',
        'link_status': '1.3.6.1.4.1.171.11.113.6.1.2.3.1.1.5'
    },
    'DES-1210-10B1': {
        'member_ports': '1.3.6.1.4.1.171.10.75.14.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.75.14.1.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.75.14.1.1.13.1.4'
    },
    'DES-1210-10B2': {
        'member_ports': '1.3.6.1.4.1.171.10.75.14.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.75.14.1.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.75.14.1.1.13.1.4'
    },
    'DES-1210-28B2': {
        'member_ports': '1.3.6.1.4.1.171.10.75.15.2.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.75.15.2.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.75.15.2.1.13.1.4'
    },
    'DGS-1100-10': {
        'member_ports': '1.3.6.1.4.1.171.10.134.2.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.134.2.1.7.6.1.4',
        'link_status': '1.3.6.1.4.1.171.10.134.2.1.1.100.1.1.4'
    },
    'DGS-1210-12TSB1': {
        'member_ports': '1.3.6.1.4.1.171.10.76.44.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.76.44.1.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.76.44.1.1.13.1.4'
    },
    'DGS-1210-20A1': {
        'member_ports': '1.3.6.1.4.1.171.10.76.31.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.76.31.1.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.76.31.1.1.13.1.4'
    },
    'DGS-1210-20B1': {
        'member_ports': '1.3.6.1.4.1.171.10.76.31.2.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.76.31.2.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.76.31.2.1.13.1.4'
    },
    'DGS-1210-28A2': {
        'member_ports': '1.3.6.1.4.1.171.10.76.28.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.76.28.1.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.76.28.1.1.13.1.4'
    },
    'DGS-1210-28B1': {
        'member_ports': '1.3.6.1.4.1.171.10.76.28.2.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.76.28.2.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.76.28.2.1.13.1.4'
    },
    'DGS-1210-28XB1': {
        'member_ports': '1.3.6.1.4.1.171.10.76.43.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.76.43.1.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.76.43.1.1.13.1.4'
    },
    'DGS-1210-28XSB1': {
        'member_ports': '1.3.6.1.4.1.171.10.76.39.1.7.6.1.3',
        'untag_ports': '1.3.6.1.4.1.171.10.76.39.1.7.6.1.5',
        'link_status': '1.3.6.1.4.1.171.10.76.39.1.1.13.1.4'
    }
}

def dns_axfr(ns, domain):
    try:
        z = dns.zone.from_xfr(dns.query.xfr(ns, domain))
        return [z[n].to_text(n).split()[0] for n in z.nodes.keys() if re.match(r'^d[eg]s-[0-9A-Za-z-]+\s', z[n].to_text(n)) and (z[n].to_text(n).split()[0] not in exclude_hosts) ]
    except:
        return None

def zbx_switch(group):
    mysqlconn = pymysql.connect(charset='utf8', host='localhost', unix_socket = '/var/run/mysqld/mysqld.sock', user = 'zabbix', passwd = '', database = 'zabbix', autocommit=True)
    cursor = mysqlconn.cursor(pymysql.cursors.DictCursor)
    def mysql_do(sqlquery):
        try:
            cursor.execute(sqlquery)
        except Exception as e:
            logger.warning(f'Ошибка: mysql_do: {e}')
            return False
        return cursor.fetchall()

    result = []
    hosts = mysql_do(f'SELECT "{group}" AS type, ip, replace(hosts.name, ".kit.ru", "") AS name FROM interface_snmp LEFT JOIN interface USING(interfaceid) LEFT JOIN hosts USING(hostid) LEFT JOIN hosts_groups USING(hostid) LEFT JOIN hstgrp USING(groupid) WHERE hstgrp.name LIKE "{group}" GROUP BY ip ORDER BY hosts.name;')

    for host in hosts:
        if host['name'] not in exclude_hosts:
            result.append(host)
    return result

def hex2ports(hexports):
    ports = []
    binports = bin(int(hexports[2:10], base=16))[2:].zfill(32)
    for i in range(0, len(binports)):
        if binports[i] == '1':
            ports.append(str(i+1))
    return ports

def ranges2ports(ranges):
    ports = []
    if len(ranges):
        for item in ranges.split(','):
            if '-' in item:
                x,y = item.split('-')
                ports.extend(range(int(x), int(y)+1))
            else:
                ports.append(int(item))
    return ports

def versiontuple(v):
    return tuple(map(int, (v.split('.'))))

class Collector:
    def __init__(self, client, community = ''):
        self.community = community
        self.session = requests.Session()
        self.switches_db = client.switches_map.switches

    def snmpwalk(self, host, oid, mpModel = 1):
        result = []
        for (errorIndication,
             errorStatus,
             errorIndex,
             varBinds) in nextCmd(SnmpEngine(),
                                  CommunityData(self.community, mpModel=mpModel),
                                  UdpTransportTarget((host, 161)),
                                  ContextData(),
                                  ObjectType(ObjectIdentity(oid)),
                                  lexicographicMode=False):

            if errorIndication:
                logger.warning(errorIndication)
                break
            elif errorStatus:
                logger.warning('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
                break
            else:
                for varBind in varBinds:
                    result.append(varBind)
        return result

    def snmpget(self, host, oid, mpModel = 1):
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(self.community, mpModel=mpModel),
                   UdpTransportTarget((host, 161)),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)),
                   lexicographicMode=False)
        )

        if errorIndication:
            logger.warning(errorIndication)
        elif errorStatus:
            logger.warning('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            return varBinds

    def run_dlink(self, host):
        varBindsMAC = self.snmpget(host['ip'], '.1.3.6.1.2.1.17.1.1.0')
        if varBindsMAC is not None and len(varBindsMAC):
            for varBind in varBindsMAC:
                hexmac = varBind[1].prettyPrint()[2:]
                swmac = ':'.join([hexmac[i:i+2] for i in range(0, len(hexmac), 2)])
        else:
            return 0
        varBindsModel = self.snmpget(host['ip'], '.1.3.6.1.2.1.1.1.0')
        if varBindsModel is not None and len(varBindsModel):
            for varBind in varBindsModel:
                try:
                    swmodel = re.search(r'D[EG]S-[0-9]{4}-?[0-9]{0,2}F?(XS?|TS|SC|TC|TG)?', varBind[1].prettyPrint(), flags=re.IGNORECASE).group(0)
                except (TypeError, AttributeError):
                    swmodel = 'unknown'
        else:
            swmodel = 'unknown'
        varBindsRev = self.snmpget(host['ip'], '.1.3.6.1.2.1.16.19.3.0')
        if varBindsRev is not None and len(varBindsRev):
            for varBind in varBindsRev:
                try:
                    swrev = re.search(r'[A-Za-z][0-9][A-Za-z0-9]{0,2}', varBind[1].prettyPrint(), flags=re.IGNORECASE).group(0)
                except (TypeError, AttributeError):
                    swrev = 'unknown'
        else:
            swrev = 'unknown'

        swtype = f'{swmodel}' if swmodel in ['DES-3526', 'DGS-3100-24TG', 'DGS-1100-10'] else f'{swmodel}{swrev}'
        oid = switchoid.get(swtype, False)
        vlans = {'member': {}, 'untag': {}}
        if oid is not False and len(oid):
            member_ports = self.snmpwalk(host['ip'], oid.get('member_ports'))
            for result in member_ports:
                data, payload = result
                vlan = str(data).split('.')[-1]
                ports = hex2ports(payload.prettyPrint())
                if int(vlan) > 1 and len(ports) > 0:
                    vlans['member'][vlan] = ports
            untag_ports = self.snmpwalk(host['ip'], oid.get('untag_ports'))
            for result in untag_ports:
                data, payload = result
                vlan = str(data).split('.')[-1]
                ports = hex2ports(payload.prettyPrint())
                if int(vlan) > 1 and len(ports) > 0:
                    vlans['untag'][vlan] = ports

            portsSpeed = {}
            speed_raw = self.snmpwalk(host['ip'], '1.3.6.1.2.1.2.2.1.5')
            for result in speed_raw:
                data, payload = result
                port = str(data).split('.')[-1]
                portsSpeed[port] = int(payload)

            portsType = {}
            if swmodel =='DES-3526':
                port_type = self.snmpwalk(host['ip'], oid.get('port_type'))
                for result in port_type:
                    data, payload = result
                    port = str(data).split('.')[-1]
                    portsType[port] = 'C' if payload in [1, 4] else 'F'
            elif swmodel == 'DGS-3100-24TG':
                for port in range(1, 25):
                    if port <= 8:
                        portsType[f'{port}'] = 'C'
                    else:
                        portsType[f'{port}'] = 'F'
            else:
                link_status = self.snmpwalk(host['ip'], oid.get('link_status'))
                for result in link_status:
                    data, payload = result
                    ptype = str(data).split('.')[-1]
                    port = str(data).split('.')[-2]
                    if re.match(r'D[EG]S-(1210|1100)+', swmodel, flags=re.IGNORECASE) is not None:
                        if payload > 1:
                            portsType[port] = 'C' if int(ptype) == 1 else 'F'
                    else:
                        if payload == 2:
                            portsType[port] = 'C' if int(ptype) in [100, 1] else 'F'

            fdb = []
            varBindsFDB = self.snmpwalk(host['ip'], ".1.3.6.1.2.1.17.7.1.2.2.1.2.%d" % management_vlan)
            for varBind in varBindsFDB:
                mac, port = varBind
                prettyMac = ':'.join([hex(int(x))[2:].zfill(2) for x in str(mac).split('.')[14:]])
                fdb.append({'mac': prettyMac, 'port': str(port)})

            try:
                self.switches_db.insert_one({'_id': host['name'], 'selfmac': swmac, 'swmodel': swmodel, 'swrev': swrev, 'last_modified': datetime.now(), 'fdb': fdb, 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}, {'ordered': False})
            except DuplicateKeyError as e:
                self.switches_db.update_many({'_id': host['name']}, {'$set': {'selfmac': swmac, 'swmodel': swmodel, 'swrev': swrev, 'last_modified': datetime.now(), 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}})
                self.switches_db.update_one({'_id': host['name']}, [{'$set': {'fdb': {'$concatArrays': ['$fdb', {'$filter': { 'input': fdb, 'cond': {'$not': {'$in': [ '$$this.mac', '$fdb.mac' ]}} }} ]}} }])
                #self.switches_db.update_many({'_id': host['name']}, [{'$set': {'selfmac': swmac, 'swmodel': swmodel, 'swrev': swrev, 'last_modified': datetime.now(), 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed, 'fdb': {'$concatArrays': ['$fdb', {'$filter': { 'input': fdb, 'cond': {'$not': {'$in': [ '$$this.mac', '$fdb.mac' ]}} }} ]} }}])
                #self.switches_db.update_many({'_id': host['name']}, {'$set': {'selfmac': swmac, 'swmodel': swmodel, 'swrev': swrev, 'last_modified': datetime.now(), 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}, '$addToSet': {'fdb': {'$each': fdb}}})
        else:
            logger.warning(f'Ошибка: run_dlink ({host}): неподдерживаемая модель {swtype}')

    def run_tplink(self, host):
        varBindsMAC = self.snmpget(host['ip'], '.1.3.6.1.2.1.17.1.1.0')
        if varBindsMAC is not None and len(varBindsMAC):
            for varBind in varBindsMAC:
                hexmac = varBind[1].prettyPrint()[2:]
                swmac = ':'.join([hexmac[i:i+2] for i in range(0, len(hexmac), 2)])
        else:
            return 0
        varBindsModel = self.snmpget(host['ip'], '.1.3.6.1.4.1.11863.6.1.1.5.0')
        if varBindsModel is not None and len(varBindsModel):
            for varBind in varBindsModel:
                swmodel = varBind[1].prettyPrint()
        else:
            swmodel = 'unknown'

        vlans = {'member': {}, 'untag': {}}
        member_ports = self.snmpwalk(host['ip'], '.1.3.6.1.4.1.11863.6.14.1.2.1.1.3')
        for result in member_ports:
            data, payload = result
            vlan = str(data).split('.')[-1]
            ports = ranges2ports(payload.prettyPrint().replace('1/0/', ''))
            if int(vlan) > 1 and len(ports) > 0:
                vlans['member'][vlan] = ports
        untag_ports = self.snmpwalk(host['ip'], '.1.3.6.1.4.1.11863.6.14.1.2.1.1.4')
        for result in untag_ports:
            data, payload = result
            vlan = str(data).split('.')[-1]
            ports = ranges2ports(payload.prettyPrint().replace('1/0/', ''))
            if int(vlan) > 1 and len(ports) > 0:
                vlans['untag'][vlan] = ports
                vlans['member'][vlan] = list(set(vlans['member'].get(vlan, []) + vlans['untag'][vlan]))

        portsName = {}
        name_raw = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.31.1.1.1.1')
        for result in name_raw:
            data, payload = result
            port = str(data).split('.')[-1]
            try:
                iface = re.search(r'1/0/([0-9]+)', str(payload), flags=re.IGNORECASE).group(1)
            except (TypeError, AttributeError):
                iface = str(payload)
            portsName[int(port)] = iface

        portsSpeed = {}
        speed_raw = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.2.2.1.5')
        for result in speed_raw:
            data, payload = result
            port = str(data).split('.')[-1]
            portsSpeed[portsName.get(int(port), port)] = int(payload)

        portsType = {}
        for port in range(1, 29):
            if port <= 24:
                portsType[f'{port}'] = 'C'
            else:
                portsType[f'{port}'] = 'F'

        fdb = []
        varBindsFDB = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.17.7.1.2.2.1.2')
        for varBind in varBindsFDB:
            data, port = varBind
            vlan = str(data).split('.')[-7]
            if int(vlan) == management_vlan:
                prettyMac = ':'.join([hex(int(x))[2:].zfill(2) for x in str(data).split('.')[14:]])
                fdb.append({'mac': prettyMac, 'port': str(port)})

        try:
            self.switches_db.insert_one({'_id': host['name'], 'selfmac': swmac, 'swmodel': swmodel, 'swrev': '', 'last_modified': datetime.now(), 'fdb': fdb, 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}, {'ordered': False})
        except DuplicateKeyError as e:
            self.switches_db.update_many({'_id': host['name']}, {'$set': {'selfmac': swmac, 'swmodel': swmodel, 'swrev': '', 'last_modified': datetime.now(), 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}})
            self.switches_db.update_one({'_id': host['name']}, [{'$set': {'fdb': {'$concatArrays': ['$fdb', {'$filter': { 'input': fdb, 'cond': {'$not': {'$in': [ '$$this.mac', '$fdb.mac' ]}} }} ]}} }])
    def run_swos(self, host):
        try:
            swos_port = {0:0, 1: 1, 2: 2, 4: 3, 8: 4, 16: 5, 32: 6}
            varBindsModel = self.snmpget(host['ip'], '.1.3.6.1.2.1.1.1.0', 0)
            if varBindsModel is not None and len(varBindsModel):
                for varBind in varBindsModel:
                    try:
                        swmodel = re.search(r'RB260GSP?', varBind[1].prettyPrint(), flags=re.IGNORECASE).group(0)
                    except (TypeError, AttributeError):
                        swmodel = 'unknown'
            else:
                swmodel = 'unknown'

            url = f'http://{host["ip"]}/!dhost.b'
            chunks = []
            try:
                r = self.session.get(url, auth=HTTPDigestAuth('admin', 'dk821nf'), stream=True)
                for chunk in r.iter_content(chunk_size=4096):
                    chunks.append(chunk)
            except:
                #chunks.append(b'{"adr":"0000cd29eab5","prt":"0x99","drp":"0x00","mir":"0x00","sts":"0x00","vid":"0x00b8"}')
                pass
            data_raw = re.sub("(\w+):'?(\w+)'?", r'"\1":"\2"',  b''.join(chunks).decode('utf-8'))
            data_json_chunks = re.findall(r'({(?:"\w+":"\w+",?)+})', data_raw)
            data_json_raw = f'[{",".join(data_json_chunks)}]'
            if (data_json_raw.find(uplink_mac.replace(':', '')) != -1):
                swmac = None
                ports_set = set()
                vlans_set = set()
                fdb = []
                vlans = {'member': {}, 'untag': {}}
                portsType = {}

                portsSpeed = {}
                speed_raw = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.2.2.1.5', 0)
                for result in speed_raw:
                    data, payload = result
                    port = str(data).split('.')[-1]
                    portsSpeed[port] = int(payload)

                response = json.loads(data_json_raw)
                for line in response:
                    port = swos_port.get(int(line['prt'], 16), 99)
                    vlan = int(line['vid'], 16)
                    mac = ':'.join(line['adr'][i:i+2] for i in range(0,12,2))
                    if port == 0:
                        swmac = mac
                        continue
                    ports_set.add(port)
                    vlans_set.add(vlan)
                    if vlan == management_vlan or mac == uplink_mac:
                        fdb.append({'mac': mac, 'port': f'{port}'})
                for vlan in vlans_set:
                    vlans['member'][f'{vlan}'] = [f'{port}' for port in ports_set]
                for port in ports_set:
                    if port <= 5:
                        portsType[f'{port}'] = 'C'
                    else:
                        portsType[f'{port}'] = 'F'

                if swmac is not None:
                    try:
                        self.switches_db.insert_one({'_id': host['name'], 'selfmac': swmac, 'swmodel': swmodel, 'swrev': '', 'last_modified': datetime.now(), 'fdb': fdb, 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}, {'ordered': False})
                    except DuplicateKeyError as e:
                        self.switches_db.update_many({'_id': host['name']}, {'$set': {'selfmac': swmac, 'swmodel': swmodel, 'swrev': '', 'last_modified': datetime.now(), 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}})
                        self.switches_db.update_one({'_id': host['name']}, [{'$set': {'fdb': {'$concatArrays': ['$fdb', {'$filter': { 'input': fdb, 'cond': {'$not': {'$in': [ '$$this.mac', '$fdb.mac' ]}} }} ]}} }])
            else:
                logger.info(f'{host["name"]} is NOT OK')
        except Exception as e:
            logger.warning(f'Ошибка: run_swos ({host}): {e}')

    def run_ros(self, host):
        try:
            if not re.match(r'^mt-[0-9A-Za-z-]+', host['name'], flags=re.IGNORECASE):
                return 0

            varBindsMAC = self.snmpget(host['ip'], '.1.3.6.1.2.1.17.1.1.0')
            if varBindsMAC is not None and len(varBindsMAC):
                for varBind in varBindsMAC:
                    hexmac = varBind[1].prettyPrint()[2:]
                    swmac = ':'.join([hexmac[i:i+2] for i in range(0, len(hexmac), 2)])
            else:
                return 0

            varBindsModel = self.snmpget(host['ip'], '.1.3.6.1.2.1.1.1.0')
            if varBindsModel is not None and len(varBindsModel):
                for varBind in varBindsModel:
                    swmodel = varBind[1].prettyPrint().replace('RouterOS ', '')
            else:
                swmodel = 'unknown'

            varBindsFW = self.snmpget(host['ip'], '.1.3.6.1.4.1.14988.1.1.7.4.0')
            if varBindsFW is not None and len(varBindsFW):
                for varBind in varBindsFW:
                    swfw = varBind[1].prettyPrint()
            else:
                return 0

            vlans = {'member': {}, 'untag': {}}

            bridgePortMap = {}
            map_raw = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.17.1.4.1.2')
            for result in map_raw:
                data, payload = result
                bridgeport = str(data).split('.')[-1]
                bridgePortMap[int(bridgeport)] = int(payload)

            portsName = {}
            name_raw = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.31.1.1.1.1')
            for result in name_raw:
                data, payload = result
                port = str(data).split('.')[-1]
                portsName[int(port)] = str(payload).replace('.', '_')

            portsSpeed = {}
            speed_raw = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.2.2.1.5')
            for result in speed_raw:
                data, payload = result
                port = str(data).split('.')[-1]
                portsSpeed[portsName.get(int(port), port)] = int(payload)

            portsType = {}
            for port_id, port_name in portsName.items():
                if re.match(r'^ether.+', port_name, flags=re.IGNORECASE) is not None:
                    portsType[port_name] = 'C'
                elif re.match(r'^sfp.+', port_name, flags=re.IGNORECASE) is not None:
                    portsType[port_name] = 'F'
                else:
                    portsType[port_name] = 'V'

            fdb_api = {}
            with ROSApi(host['ip']) as api:
                for fdb in api.talk('/interface/bridge/host/print'):
                    fdb_api[fdb['mac-address'].lower()] = fdb['on-interface']

            varBindsFDB = self.snmpwalk(host['ip'], '.1.3.6.1.2.1.17.4.3.1.2')
            for varBind in varBindsFDB:
                mac, port = varBind
                prettyMac = ':'.join([hex(int(x))[2:].zfill(2) for x in str(mac).split('.')[11:]])

                if prettyMac not in fdb_api and int(port) != 0:
                    if versiontuple(swfw) > versiontuple('6.46.8'):
                        port = bridgePortMap.get(int(port), int(port))

                    if port in portsName:
                        fdb_api[prettyMac] = portsName[port]

            if not uplink_mac in fdb_api:
                logger.warning(f'Ошибка: run_ros ({host}): не найден мак шлюза в fdb')
                return 0

            fdb = []
            fdb_api.pop(swmac, None)
            for mac, iface in fdb_api.items():
                if re.match(r'^(eth|sfp|combo|admin|skorop).+', iface, flags=re.IGNORECASE) is not None:
                    fdb.append({'mac': mac, 'port': iface.replace('.', '_')})

            if swmac is not None:
                try:
                    self.switches_db.insert_one({'_id': host['name'], 'selfmac': swmac, 'swmodel': swmodel, 'swrev': '', 'last_modified': datetime.now(), 'fdb': fdb, 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}, {'ordered': False})
                except DuplicateKeyError as e:
                    self.switches_db.update_many({'_id': host['name']}, {'$set': {'selfmac': swmac, 'swmodel': swmodel, 'swrev': '', 'last_modified': datetime.now(), 'vlans': vlans, 'ptype': portsType, 'pspeed': portsSpeed}})
                    self.switches_db.update_one({'_id': host['name']}, [{'$set': {'fdb': {'$concatArrays': ['$fdb', {'$filter': { 'input': fdb, 'cond': {'$not': {'$in': [ '$$this.mac', '$fdb.mac' ]}} }} ]}} }])
        except Exception as e:
            logger.warning(f'Ошибка: run_ros ({host}): {e}')

class Pworker(mp.Process):
    def __init__(self, mpqueue):
        mp.Process.__init__(self)
        self.daemon = True
        self.mpqueue = mpqueue

    def __del__(self):
        logger.info(f'[{self.name}] stop')

    def run(self):
        logger.info(f'[{self.name}] start')

        client = MongoClient()
        collector = Collector(client)

        while True:
            payload = self.mpqueue.get()
            if payload is None:
                del collector
                break
            logger.info(f'[{self.name}] working on data {payload}')
            if payload['type'] == 'D-Link%':
                collector.run_dlink(payload)
            elif payload['type'] == 'MikroTik SwOS':
                collector.run_swos(payload)
            elif payload['type'] == 'MikroTik RouterOS':
                collector.run_ros(payload)
            elif payload['type'] == 'TP-Link%':
                collector.run_tplink(payload)

def separation(rel_data):
    # сравниваем маки на даунлинках каждого свитча с каждым
    for host in rel_data:
        childs = [ch['_id'] for ch in host['childs']]
        for subhost in [x for x in rel_data if x['_id'] != host['_id']]:
            subchilds = [subch['_id'] for subch in subhost['childs']]
            # если есть общие свитчи на даунлинках
            intersect_childs = list(set(childs) & set(subchilds))
            if len(intersect_childs):
                # и сам сабхост есть на даунлинке вышестоящего, то маки сабхоста удаляются с вышестоящего
                if subhost['_id'] in childs:
                     host['childs'][:] = [child for child in host['childs'] if child.get('_id') not in intersect_childs]

def relationship():
    relationship_db.drop()
    rel_data = []
    # добавляем метку с аплинк портом и оставляем только даунлинк fdb
    for downlink_switch in switches_db.aggregate([{
                                           '$addFields': {
                                               'uplink': {
                                                   '$arrayElemAt': [{
                                                       '$map': {
                                                            'input': {
                                                                '$filter': {
                                                                    'input': '$fdb',
                                                                    'as': 'item',
                                                                    'cond': {'$eq': ['$$item.mac', uplink_mac]}
                                                                }
                                                            },
                                                            'as': 'el',
                                                            'in': '$$el.port'
                                                        }
                                                   }, 0]
                                               }
                                           }
                                           },
                                           {'$project': {
                                               'selfmac': 1,
                                               'swmodel': 1,
                                               'swrev': 1,
                                               'last_modified': 1,
                                               'vlans': 1,
                                               'ptype' : 1,
                                               'pspeed' : 1,
                                               'uplink': 1,
                                               'fdb': {
                                                   '$filter': {
                                                       'input': '$fdb',
                                                       'as': 'item',
                                                       'cond': {
                                                           '$and': [
                                                               {'$ne': ['$$item.port', '$uplink']},
                                                               {'$ne': ['$$item.port', '0']}
                                                           ]
                                                       }
                                                   }
                                               }
                                           }
                                        }]):
        childs = []
        # идем по макам на даунлинк порте
        for downlink_switch_fdb in downlink_switch['fdb']:
            # достаем информацию о очередном свитче по маку
            for switch in switches_db.find({'selfmac': downlink_switch_fdb['mac']}, {'_id': 1, 'selfmac': 1, 'swmodel': 1, 'swrev': 1, 'last_modified': 1, 'vlans': 1, 'ptype': 1, 'pspeed': 1}):
                if strict_relationship:
                    # находим аплинковый порт с маком вышестоящего свитча
                    for uplink_switch in switches_db.find({'selfmac': switch['selfmac'], 'fdb.mac': downlink_switch['selfmac']}, {'fdb.$': 1}):
                        childs.append({'port': downlink_switch_fdb['port'], '_id': switch['_id'], 'swmodel': switch['swmodel'], 'swrev': switch['swrev'], 'last_modified': switch['last_modified'].strftime("%H:%M:%S %d.%m.%Y"), 'vlans': switch['vlans'], 'ptype': switch['ptype'], 'pspeed': switch['pspeed'], 'uplink': uplink_switch['fdb'][0]['port'] })
                else:
                    # находим аплинковый порт с маком шлюза
                    for uplink_switch in switches_db.find({'selfmac': switch['selfmac'], 'fdb.mac': uplink_mac}, {'fdb.$': 1}):
                        childs.append({'port': downlink_switch_fdb['port'], '_id': switch['_id'], 'swmodel': switch['swmodel'], 'swrev': switch['swrev'], 'last_modified': switch['last_modified'].strftime("%H:%M:%S %d.%m.%Y"), 'vlans': switch['vlans'], 'ptype': switch['ptype'], 'pspeed': switch['pspeed'], 'uplink': uplink_switch['fdb'][0]['port'] })
        if len(childs) > 0 and downlink_switch.get('uplink', False):
            rel_data.append({'_id': downlink_switch['_id'], 'swmodel': downlink_switch['swmodel'], 'swrev': downlink_switch['swrev'], 'last_modified': downlink_switch['last_modified'].strftime("%H:%M:%S %d.%m.%Y"), 'vlans': downlink_switch['vlans'], 'ptype': downlink_switch['ptype'], 'pspeed': downlink_switch['pspeed'], 'uplink': downlink_switch['uplink'], 'childs': childs})
    separation(rel_data)
    try:
        relationship_db.insert_many(rel_data, ordered=False)
    except BulkWriteError as e:
        pprint(e.details)

def main():
    if collecting:
        logger.info('collecting switches')
        #hosts = dns_axfr('1.1.1.1', 'kit.ru')

        dlink_hosts = []
        swos_hosts = []
        ros_hosts = []
        tplink_hosts = []
        dlink_hosts = zbx_switch('D-Link%')
        swos_hosts = zbx_switch('MikroTik SwOS')
        ros_hosts = zbx_switch('MikroTik RouterOS')
        tplink_hosts = zbx_switch('TP-Link%')

        logger.info('collecting switches data')
        mpqueue = mp.Queue()
        processes = []

        for w in range(workers):
            p = Pworker(mpqueue)
            p.name = 'process-%d' % w
            p.start()
            processes.append(p)

        minute = datetime.now().minute
        limit = int(len(dlink_hosts) / repoll_time + 0.99)
        logger.info("minute=%s from=%s to=%s" % (minute, limit * (minute % repoll_time), (limit * (minute % repoll_time)) + limit))

        for idx, host in enumerate(dlink_hosts):
            if idx >= limit * (minute % repoll_time) and idx < (limit * (minute % repoll_time)) + limit:
                mpqueue.put(host)

        for idx, host in enumerate(swos_hosts):
            mpqueue.put(host)

        for idx, host in enumerate(ros_hosts):
            mpqueue.put(host)

        for idx, host in enumerate(tplink_hosts):
            mpqueue.put(host)

        for i in range(workers):
            mpqueue.put(None)
        for p in processes:
            p.join()

    logger.info('delete old switches data')
    switches_db.delete_many({ 'last_modified': { '$lte': datetime.now() - timedelta(days=3) } })

    logger.info('processing data')
    relationship()

if __name__ == '__main__':
    try:
        client = MongoClient()
        db = client.switches_map

        switches_db = db.switches
        relationship_db = db.relationship

        if len(sys.argv) > 1 and sys.argv[1] in ('-drop', '--drop'):
            logger.info('drop switches data')
            db.switches.drop()
        main()
#        for switch in switches_db.find({'_id': 'des-oz6p1'}):
#        for switch in relationship_db.find({}):
#        for switch in relationship_db.aggregate([ { '$match': { '_id': { '$nin': relationship_db.distinct('childs._id') }}},
#                                                 { '$project': { '_id' : 1 }}
#                                                 ]):
#            pprint(switch)
#        switches_db.update_many({'_id': 'des-oz6p4'}, {'$set': {'swmodel': 'unknown', 'swrev': 'unknown'}})
    except KeyboardInterrupt:
        print()