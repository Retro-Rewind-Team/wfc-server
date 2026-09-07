# rwfc

Retro Wi-Fi Connection is a fork of WiiLink WFC. This repository contains numerous changes to WWFC to support Retro Rewind.

## Changes from WWFC

- Extended and rewritten APIs to facilitate [rwfc-web](https://github.com/Retro-Rewind-Team/rwfc-web/), [wfc-bot](https://github.com/Retro-Rewind-Team/wfc-bot/)
  - Discord linking with a license
  - Improved moderation
    - Querying a profile for bans and other identifiers
    - Querying a Mii for a given profile
    - Searching for users by a given identifiers
  - Setting the Message of the Day without resetting the server
- Extended max VR (Up to 30k, Retro Rewind's higher VR is handled client side)
- Client hash checking to ensure only clients on the most up-to-date version may log in
  - See [Hashing](#hashing)
- Adjustments to ban logic to better facilitate nand-less play
- Improved translations and extended language support
- Reporting of kick/ban reasons to the client
- QR2 kick ordering to force clients to drop kicked clients
- Open Host reporting via the group's API

## Setup

**PREFACE**: All RWFC projects are codependent, in that a mix and match of RWFC
and WFC or vanilla Mario Kart Wii projects and tooling are not guaranteed to
work or be compatible. This fork of wfc-server **WILL NOT** function without
using Retro Rewind's modified payload and modified Pulsar.

You will need:
- A Go compiler (minimum 1.25.5)
- A copy of the payload (see [wfc-patcher-wii](https://github.com/Retro-Rewind-Team/wfc-patcher-wii/) for instructions)
    - The payload's `dist` folder should be copied into the same folder as the executable and named `payload`
- PostgreSQL

1. Create a PostgreSQL database. Note the database name, username, and
   password.
2. Use the `schema.sql` found in the root of this repo and import it into your
   PostgreSQL database.
3. Copy `config-example.xml` to `config.xml` and insert all the correct data.
4. Run `go build`. The executable `wwfc` will appear in the current directory.

#### Hashing

For hashing to work, both clients and the server must be configured properly.
Clients submit a PackID, a Version, and a Hash on connecting, which are
configured in rr-pulsar. These fields must be populated in the server if you do
not disable `enableHashCheck` in `config.xml`. You can set them in one of two
ways:

##### wfc-bot
For this you must host and configure an instance of
[wfc-bot](https://github.com/Retro-Rewind-Team/wfc-bot/). You can then use the
`hash` command to submit your Code.pul. Clients must then connect with this
exact Code.pul. See the [Note](#note)

##### pulsar-tools
1. Download the latest release of
   [pulsar-tools](https://github.com/ppebb/pulsar-tools/releases).
2. Run the hash command, and supply your Code.pul
3. Manually insert the hashes returned by pulsar-tools into your database
4. The database contains a hashes table, which contains the fields pack_id, version, hash_pal, hash_ntscu, hash_ntscj, hash_ntsck. Insert according to these fields.

**NOTE**: Since these tools were developed with RWFC in mind, you will either have to
modify the bot and server source code to display the correct names, or you can
reuse one of the existing slots and accept they will have the wrong name.
