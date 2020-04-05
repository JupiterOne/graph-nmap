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
        displayName: hostname || addresses.ipAddress || addresses.macAddress,
        active: status === 'up',
      }

      const entity = {
        entityKey: `nmap:${hostname}:${addresses.macAddress}:${addresses.ipAddress}`,
        entityType: 'nmap_discovered_host',
        entityClass: 'Host',
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

function processPorts(ports: NmapPorts | undefined) {
  if (!ports) {
    return {};
  }
  
  const openPorts: NmapPort[] = [];
  if (Array.isArray(ports.port)) {
    ports.port.forEach(p => {
      const state = typeof p.state === 'string' ? p.state : p.state.state;
      if (state === 'open') {
        openPorts.push(p);
      }
    });
  }
  else if (ports.port) {
    const state = typeof ports.port.state === 'string' 
      ? ports.port.state 
      : ports.port.state.state;
    if (state === 'open') {
      openPorts.push(ports.port);
    }
  }

  return {
    openPorts: openPorts.map(p => p.portid).map(p => parseInt(p)),
    services: openPorts.map(p => p.service?.name),
  };
}

function processOsDetails(os: NmapOS | undefined) {
  if (!os) {
    return {};
  }

  return {
    platform: os.osclass?.osfamily.toLowerCase(),
    osName: os.osmatch?.name,
    ports: os.portused?.map(p => p.portid).map(p => parseInt(p)),
  }
} 