import { DataModel } from "@jupiterone/jupiter-managed-integration-sdk";
import { NmapOutput, NmapHost, NmapPorts, NmapOS, NmapAddress, NmapPort } from "../types/nmap";

export function toHostEntities(data: NmapOutput) {
  const entities = [];

  let hosts: NmapHost[] = [];
  if (data.nmaprun.host) {
    hosts = Array.isArray(data.nmaprun.host) ? data.nmaprun.host : [data.nmaprun.host];
  }

  for (const host of hosts) {
    try {
      const status = host.status.state;

      if (status !== 'up') {
        // skip host
        continue;
      }

      const entityClass = ['Host'];
      const deviceType = getDeviceType(host.ports);
      
      // https://nmap.org/book/osdetect-device-types.html
      if (deviceType) {
        if (deviceType.match(/balancer|bridge|router|proxy/i)) {
          entityClass.push('Gateway');
        }
        else if (deviceType.match(/firewall/i)) {
          entityClass.push('Firewall');
        }
        else if (deviceType.match(/print/i)) {
          entityClass.push('Printer');
        }
        else if (deviceType.match(/phone|device/i)) {
          entityClass.push('Device');
        }
      }

      let hostname;
      let aliases;
      if (typeof host.hostnames === 'string') {
        if (host.hostnames.trim().length > 0) {
          hostname = host.hostnames;
        }
      }
      else {
        hostname = host.hostnames.hostname.filter(h => h.type === 'user')[0].name;
        aliases = host.hostnames.hostname.map(h => h.name);
        if (!hostname && aliases.length > 0) {
          hostname = aliases[0];
        }
      }

      const addresses = processAddresses(host.address);
      
      const entityProperties = {
        ...addresses,
        ...processOsDetails(host.os),
        ...processPorts(host.ports),
        hostname,
        aliases,
        status,
        deviceType,
        active: status === 'up',
      }

      entityProperties.displayName = 
        hostname || 
        entityProperties.afpServerName || 
        entityProperties.serverName || 
        entityProperties.netbiosName ||
        addresses.ipAddress || 
        addresses.macAddress;

      const entity = {
        entityKey: `nmap:${hostname}:${addresses.macAddress}:${addresses.ipAddress}`,
        entityType: 'nmap_discovered_host',
        entityClass,
        properties: entityProperties,
        _rawData: host,
      };

      entities.push(entity);
    }
    catch (err) {
      console.log('Error processing host. Skipping to next.');
      console.log({ err });
      continue;
    }
  }
  return entities;
}

function processAddresses(addresses: NmapAddress | NmapAddress[] | undefined) {
  if (!addresses) {
    return {};
  }

  let isPublic = false;
  const ipAddress = [];
  const macAddress = [];
  const vendor = [];

  for (const address of (Array.isArray(addresses) ? addresses : [addresses])) {
    if (address.addrtype === 'mac') {
      macAddress.push(address.addr);
      if (address.vendor) {
        vendor.push(address.vendor);
      }
    }
    else {
      if (DataModel.ipUtil.isPublicIp(address.addr)) {
        isPublic = true;
      }
      ipAddress.push(address.addr);
    }
  }

  return {
    public: isPublic,
    ipAddress: ipAddress.length === 1 ? ipAddress[0] : ipAddress,
    macAddress: macAddress.length === 1 ? macAddress[0] : macAddress,
    vendor: vendor.length === 1 ? vendor[0] : vendor,
  };
}

function getDeviceType(ports: NmapPorts | undefined) {
  if (ports?.port) {
    for (const port of (Array.isArray(ports.port) ? ports.port : [ports.port])) {
      if (port.service?.devicetype) {
        return port.service.devicetype;
      }
    }
  }
}

const REGEX_AFPSERVER = /afpserver\/([\w,.@-]+)/i;
const REGEX_SERVER_NAME = /Server Name: ((?!true|false)[\w,.-]+)/i;
const REGEX_MACHINE_TYPE = /Machine Type: ([\w,.-]+)/i;
const REGEX_NETBIOS_NAME = /NetBIOS Name: ([\w.-]+)/i;

function processPorts(ports: NmapPorts | undefined) {
  if (!ports) {
    return {};
  }
  
  const openPortsList: NmapPort[] = [];
  if (Array.isArray(ports.port)) {
    ports.port.forEach(p => {
      const state = typeof p.state === 'string' ? p.state : p.state.state;
      if (state === 'open') {
        openPortsList.push(p);
      }
    });
  }
  else if (ports.port) {
    const state = typeof ports.port.state === 'string' 
      ? ports.port.state 
      : ports.port.state.state;
    if (state === 'open') {
      openPortsList.push(ports.port);
    }
  }

  const openPorts: number[] = [];
  const services: string[] = [];
  const additionalDetails: any = {};
  openPortsList.forEach(p => {
    openPorts.push(parseInt(p.portid));

    if (p.service) {
      services.push(p.service.name);

      if (p.script?.id === 'afp-serverinfo') {
        const matchAfpServer = p.script?.output.match(REGEX_AFPSERVER);
        const matchServerName = p.script?.output.match(REGEX_SERVER_NAME);
        const matchMachineType = p.script?.output.match(REGEX_MACHINE_TYPE);

        additionalDetails.afpServerName = matchAfpServer && matchAfpServer[1];
        additionalDetails.serverName = matchServerName && matchServerName[1];
        additionalDetails.machineType = matchMachineType && matchMachineType[1];
      }
      else if (p.script?.id === 'nbstat') {
        const matchNetBiosName = p.script?.output.match(REGEX_NETBIOS_NAME);
        additionalDetails.netbiosName = matchNetBiosName && matchNetBiosName[1];
      }
    }
  });

  return {
    openPorts,
    services,
    ...additionalDetails
  };
}

function processOsDetails(os: NmapOS | undefined) {
  if (!os) {
    return {};
  }

  let ports;
  if (Array.isArray(os.portused)) {
    ports = os.portused.map(p => p.portid).map(p => parseInt(p));
  }
  else if (os.portused) {
    ports = [parseInt(os.portused.portid)];
  }

  return {
    platform: os.osclass?.osfamily.toLowerCase(),
    osName: !Array.isArray(os.osmatch) && os.osmatch?.name,
    ports,
    type: os.osclass?.type,
  }
} 