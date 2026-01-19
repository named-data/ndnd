/**
 * KeychainJS interface for storing keys and certificates.
 *
 * @license Apache-2.0
 */
export interface KeyChainJS {
    // Get all keys and certificates in the keychain
    list(): Promise<Uint8Array[]>;

    // Write a key or certificate to the keychain
    write(name: string, blob: Uint8Array): Promise<void>;

    // Delete a key or certificate from the keychain
    delete(name: string): Promise<void>;
}

import Dexie from 'dexie';

/**
 * KeychainJS implementation using Dexie.
 *
 * @license Apache-2.0
 */
export class KeyChainDexie implements KeyChainJS {
  private db = new Dexie('keychain') as Dexie & {
    keys: Dexie.Table<{ name: string; blob: Uint8Array }, number>;
  };

  constructor() {
    this.db.version(1).stores({
      keys: 'name',
    });
  }

  public async list() {
    const list = await this.db.keys.toArray();
    return list.map((k) => k.blob);
  }

  public async write(name: string, blob: Uint8Array) {
    await this.db.keys.put({ name, blob });
  }

  public async delete(name: string) {
    await this.db.keys.delete(name);
  }
}
