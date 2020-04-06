export interface NmapOutput {
  nmaprun: {
    scanner: "nmap";
    args: string;
    start: string; // should parse to datetime number
    startstr: string;
    version: string;
    xmloutputversion: string;

    scaninfo: {
      type: string;
      protocol: string;
      numservices: string;
      services: string;
    };

    verbose: {
      level: string;
    };
    debugging: {
      level: string;
    };

    taskbegin: NmapTask[];
    taskend: NmapTask[];

    runstats: {
      finished: {
        time: string; // should parse to datetime number
        timestr: string;
        elapsed: string;
        summary: string;
        exit: string;
      },
      hosts: {
        up: string; // should parse to number
        down: string; // should parse to number
        total: string; // should parse to number
      }
    }

    host: NmapHost | NmapHost[];
  };
}

export interface NmapHost {
  status: {
    state: "up" | "down",
    reason: string;
    reason_ttl: string; // should parse to number
  };
  address: NmapAddress | NmapAddress[];
  hostnames: string | {
    hostname: NmapHostname[];
  };
  ports?: NmapPorts;
  os?: NmapOS;
  uptime?: {
    seconds: string; // should parse to number
    lastboot: string; // Datetime string
  };
  distance?: {
    value: string; // should parse to number
  };
  hostscript?: {
    script: NmapScript | NmapScript[];
  };
  tcpsequence?: NmapSequence;
  ipidsequence?: NmapSequence;
  tcptssequence?: NmapSequence;
  trace?: NmapTrace;
  times?: Attributes;
}

export interface NmapAddress {
  addr: string;
  addrtype: "ipv4" | "ipv6" | "mac";
  vendor?: string;
}

export interface NmapHostname {
  name: string;
  type: "user" | "PTR";
}

export interface NmapPorts {
  extraports?: {
    state: "open" | "closed" | "filtered",
    count: string; // should parse to number
    extrareasons: {
      reason: string;
      count: string; // should parse to number
    };
  };
  port?: NmapPort | NmapPort[];
}

export interface NmapPort {
  portid: string; // should parse to number
  protocol?: string;
  proto?: string
  state: string | NmapPortState;
  service?: NmapService;
  script?: NmapScript | NmapScript;
}

export interface NmapPortState {
  state: string;
  reason: string;
  reason_ttl: string; // should parse to number
}

export interface NmapOS {
  portused?: NmapPort | NmapPort[],
  osclass?: NmapOSClass;
  osmatch?: NmapOSMatch | NmapOSMatch[]
}

export interface NmapOSClass {
  type: string; // e.g. "general purpose"
  vendor: string; // e.g. "Linux"
  osfamily: string; // e.g. "Linux"
  osgen: string;  // e.g. "2.6.X"
  accuracy: string; // should parse to number
  cpe: string | string[];
}

export interface NmapOSMatch {
  name: string; // e.g. "Linux 2.6.39"
  accuracy: string; // accuracy score (0-100); should parse to number
  line: string; // should parse to number
  osclass?: NmapOSClass; 
}

export interface NmapService {
  name: string;
  product: string;
  version?: string;
  extrainfo?: string;
  ostype?: string;
  devicetype?: string; // e.g. "router"
  tunnel?: string; // e.g. "ssl"
  method: string; // e.g. "probed"
  conf: string; // confidence score (0-10); should parse to number
  cpe: string | string[]
}

export interface NmapScript {
  id: string;
  output: string;
  elem: string | string[] | object;
  table?: object;
}

export interface NmapSequence {
  index?: string; // should parse to number
  difficulty?: string;
  class?: string;
  values: string; // comma separated number values
}

export interface NmapTask {
  task: string;
  time: string; // should parse to datetime number
}

export interface NmapTrace {
  port: string; // should parse to number
  proto: string;
  hop: NmapTraceHop[];
}

export interface NmapTraceHop {
  ttl: string; // should parse to number
  ipaddr: string;
  rtt: string; // should parse to number
  host: string;
}

interface Attributes {
  [_key: string]: string;
}