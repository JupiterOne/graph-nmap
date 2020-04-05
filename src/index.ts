import 'dotenv/config';

import JupiterOneClient from '@jupiterone/jupiterone-client-nodejs';
import * as xml2js from 'xml2js';
import pThrottle from 'p-throttle';

import { NmapOutput } from '../types/nmap';
import { toHostEntities } from './converter';

// throttle to stay within API rate limit
const DEFAULT_THROTTLE = 4000;

// for debugging use; script will not push entities to J1 in debug mode
const DEBUG = false;

// Set the DEFAULT_GATEWAY value to an IP Address (e.g. '192.168.1.1') will add
// a `defaultGateway` property to each discovered host entity.
const DEFAULT_GATEWAY = null;

function gatherConfig () {
  const config = {
    j1AccessToken: process.env.J1_ACCESS_TOKEN,
    j1Account: process.env.J1_ACCOUNT,
    dev: process.env.DEV
  };

  if (config.j1AccessToken && config.j1Account) {
    return config;
  }
  else {
    throw new Error("Missing value in config. Make sure env values are set properly");
  }
}


async function ingestData(data: any) {
  const config = gatherConfig();
  const j1Client = 
    await new JupiterOneClient({
      account: config.j1Account as string, 
      accessToken: config.j1AccessToken, 
      dev: (config.dev === 'true') 
    }).init();

  const parser = new xml2js.Parser({ mergeAttrs: true, explicitArray: false });

  try {
    const json: NmapOutput = await parser.parseStringPromise(data);

    if (DEBUG) {
      console.log(JSON.stringify(json, null, 2));
    }

    if (json) {
      const newEntities = toHostEntities(json);
      newEntities.forEach(entity => {
        if (DEFAULT_GATEWAY) {
          if (entity.properties.ipAddress === DEFAULT_GATEWAY) {
            entity.entityClass = ['Host', 'Gateway'];
          } else {
            Object.assign(entity.properties, {
              defaultGateway: DEFAULT_GATEWAY,
            });
          };
        }
      });
      await createEntities(j1Client, newEntities);
    }
  }
  catch (err) {
    console.error({ err });
  }
}


async function run () {
  const stdin = process.openStdin();
  let data = "";

  stdin.on('data', function(chunk) {
    data += chunk;
  });

  stdin.on('end', function() {
    // Remove comment lines
    ingestData(data.replace(/^#.+$/gm, ''));
  });

}

async function createEntities(j1Client: any, entities: any) {
  if (DEBUG) {
    return;
  }

  const throttled = pThrottle(async (e: any) => {
    const classLabels = Array.isArray(e.entityClass)
      ? e.entityClass
      : [e.entityClass];
    const res = await j1Client.createEntity(
      e.entityKey,
      e.entityType,
      classLabels,
      e.properties
    );
    
    const entityId = res.vertex.entity._id;

    if (e._rawData) {
      await j1Client.upsertEntityRawData(
        entityId, 
        'default', 
        'application/json', 
        e._rawData
      );
    }

    return entityId;
  }, 1, DEFAULT_THROTTLE);
  
  for (const e of entities) {
    const entityId = await throttled(e);
    console.log(`Created entity ${entityId}.`);
  }

  console.log("Finished creating entities in JupiterOne.");
}

run().catch(console.error);