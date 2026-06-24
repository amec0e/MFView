// ── CARD TYPE CONSTANTS ──
// Sources: cmdhfmf.c, cmdhfmfp.c, cmdhfmfu.c
// MIFARE Classic sizes from CmdHF14AMfView (cmdhfmf.c 8541-8549)
// MF Plus from cmdhfmfp.c (SAK/ATQA detection)
// MF Ultralight from cmdhfmfu.c MAX_* constants (4-byte pages)

const BLOCK_MFC  = 16; // MFBLOCK_SIZE — Classic / Plus
const BLOCK_MFU  = 4;  // MFU_BLOCK_SIZE — Ultralight

// ── CLASSIC / PLUS CARD DB (keyed by byte size) ──
const CARD_DB = {
  320:  { name: 'MIFARE Classic Mini (S20)', short: 'Mini',   family: 'classic', sectors: 5,  blocks: 20,  ev1: false },
  1024: { name: 'MIFARE Classic 1K (S50)',   short: '1K',     family: 'classic', sectors: 16, blocks: 64,  ev1: false },
  1152: { name: 'MIFARE Classic 1K EV1',     short: '1K EV1', family: 'classic', sectors: 16, blocks: 64,  ev1: true  },
  2048: { name: 'MIFARE Classic 2K',         short: '2K',     family: 'classic', sectors: 32, blocks: 128, ev1: false },
  4096: { name: 'MIFARE Classic 4K (S70)',   short: '4K',     family: 'classic', sectors: 40, blocks: 256, ev1: false },
};

// MIFARE Plus uses the same 16-byte block layout and sizes as Classic (2K = 128 blocks,
// 4K = 256 blocks), so Plus dumps fall through to the Classic entries above by size.
// SL1 is byte-for-byte identical to Classic and renders correctly via the Classic path —
// no special-casing is needed or possible (SL1 shares SAK 08/18 with genuine Classic).
// SL2/SL3 blocks are AES-encrypted; their SAK values are named in SAK_TYPES for display
// only — there is no separate decode path for them.

// ── ULTRALIGHT TYPE DB (keyed by page count from MAX_* defines in cmdhfmfu.c) ──
const MFU_DB = [
  // { pages, name } — ordered largest first for matching
  { pages: 0xE6+1, name: 'NTAG 216 / 216F',      short: 'NTAG216'  },
  { pages: 0xE9+1, name: 'NTAG I2C 1K/2K',        short: 'NTAGI2C'  },
  { pages: 0x86+1, name: 'NTAG 215',               short: 'NTAG215'  },
  { pages: 0x4B+1, name: 'NTAG 224 DNA',           short: 'NTAG224'  },
  { pages: 0x3B+1, name: 'NTAG 223 DNA',           short: 'NTAG223'  },
  { pages: 0x37+1, name: 'MIFARE Ultralight AES',  short: 'UL AES'   },
  { pages: 0x2F+1, name: 'MIFARE Ultralight C',    short: 'UL-C'     },
  { pages: 0x2C+1, name: 'NTAG 213 / 213F / 213C', short: 'NTAG213'  },
  { pages: 0x29+1, name: 'NTAG 203',               short: 'NTAG203'  },
  { pages: 0x28+1, name: 'MIFARE Ultralight EV1 (128)',short:'UL EV1-128'},
  { pages: 0x25+1, name: 'SLE 4428 / My-d Move',   short: 'MyD Move' },
  { pages: 0x13+1, name: 'NTAG 210 / UL EV1 (48)', short: 'NTAG210'  },
  { pages: 0x0F+1, name: 'MIFARE Ultralight',       short: 'UL'       },
  { pages: 0x0A+1, name: 'MIFARE Ultralight Nano',  short: 'UL Nano'  },
];

function detectMFU(totalBytes) {
  const pages = Math.floor(totalBytes / BLOCK_MFU);
  // Exact match first
  for (const t of MFU_DB) {
    if (pages === t.pages) return { ...t, pages, family: 'ultralight' };
  }
  // Closest match (partial dump)
  for (const t of MFU_DB) {
    if (pages <= t.pages) return { ...t, pages, family: 'ultralight' };
  }
  return { pages, name: 'MIFARE Ultralight (unknown)', short: 'UL?', family: 'ultralight' };
}

// ── GEOMETRY HELPERS (Classic / Plus) ──
function firstBlk(s)   { return s < 32 ? s * 4 : 128 + (s - 32) * 16; }
function blksPerSec(s) { return s < 32 ? 4 : 16; }
function secOfBlk(b)   { return b < 128 ? Math.floor(b / 4) : 32 + Math.floor((b - 128) / 16); } // block → sector (currently unused helper)

// ── ACCESS CONDITIONS (Classic / Plus SL1) ──
// Exactly matches mfValidateAccessConditions() from mifare4.c lines 77-86
// and mf_get_accesscondition() / mfGetAccessConditionsDesc() lines 126-131
// data[0]=b6, data[1]=b7, data[2]=b8 of the sector trailer block
//
// Nibble layout (NIBBLE_LOW = bits 3:0, NIBBLE_HIGH = bits 7:4):
//   nd1 = NIBBLE_LOW(b6)   ~C1 inverted
//   nd2 = NIBBLE_HIGH(b6)  ~C2 inverted
//   nd3 = NIBBLE_LOW(b7)   ~C3 inverted
//   d1  = NIBBLE_HIGH(b7)   C1 true
//   d2  = NIBBLE_LOW(b8)    C2 true
//   d3  = NIBBLE_HIGH(b8)   C3 true
// Valid if: nd1==(d1^0xF) && nd2==(d2^0xF) && nd3==(d3^0xF)
//
// Per-block condition index (from mf_get_accesscondition, blockn=0..3):
//   cond = ((d1>>blockn)&1)<<2 | ((d2>>blockn)&1)<<1 | ((d3>>blockn)&1)

function parseACL(b6, b7, b8) {
  const nd1 = b6 & 0x0F;        // NIBBLE_LOW(b6)  = ~C1
  const nd2 = (b6 >> 4) & 0x0F; // NIBBLE_HIGH(b6) = ~C2
  const nd3 = b7 & 0x0F;        // NIBBLE_LOW(b7)  = ~C3
  const d1  = (b7 >> 4) & 0x0F; // NIBBLE_HIGH(b7) =  C1
  const d2  = b8 & 0x0F;        // NIBBLE_LOW(b8)  =  C2
  const d3  = (b8 >> 4) & 0x0F; // NIBBLE_HIGH(b8) =  C3

  const valid = (nd1 === (d1 ^ 0xF)) && (nd2 === (d2 ^ 0xF)) && (nd3 === (d3 ^ 0xF));

  // Extract per-block condition index (0..7) for blocks 0-3
  const c1 = [0,1,2,3].map(i => (d1 >> i) & 1);
  const c2 = [0,1,2,3].map(i => (d2 >> i) & 1);
  const c3 = [0,1,2,3].map(i => (d3 >> i) & 1);

  return { c1, c2, c3, valid };
}
function acKey(c1, c2, c3) { return (c1 << 2) | (c2 << 1) | c3; }

// Access conditions tables — exactly match mifare4.c MFAccessConditions[] and MFAccessConditionsTrailer[]
// Index = cond = (C1<<2)|(C2<<1)|C3 for each block (0-3)

const DATA_AC = {
  0: { rd:'A|B', wr:'A|B', inc:'A|B', dec:'A|B', label:'read AB write AB increment AB decrement transfer restore AB' },
  1: { rd:'A|B', wr:'—',   inc:'—',   dec:'A|B', label:'read AB decrement transfer restore AB' },
  2: { rd:'A|B', wr:'—',   inc:'—',   dec:'—',   label:'read AB' },
  3: { rd:'B',   wr:'B',   inc:'—',   dec:'—',   label:'read B write B' },
  4: { rd:'A|B', wr:'B',   inc:'—',   dec:'—',   label:'read AB write B' },
  5: { rd:'B',   wr:'—',   inc:'—',   dec:'—',   label:'read B' },
  6: { rd:'A|B', wr:'B',   inc:'B',   dec:'A|B', label:'read AB write B increment B decrement transfer restore AB' },
  7: { rd:'—',   wr:'—',   inc:'—',   dec:'—',   label:'no access' },
};

const ST_AC = {
  0: { kaR:'A', kaW:'A',   aclR:'A',   aclW:'A',   kbR:'A',   kbW:'A',   kbRead:true,  label:'Key B readable — read A by A; read ACCESS by A; read/write B by A' },
  1: { kaR:'—', kaW:'A',   aclR:'A',   aclW:'A',   kbR:'A',   kbW:'A',   kbRead:true,  label:'Key B readable — write A by A; read/write ACCESS by A; read/write B by A' },
  2: { kaR:'—', kaW:'—',   aclR:'A',   aclW:'—',   kbR:'A',   kbW:'—',   kbRead:true,  label:'Key B readable — read ACCESS by A; read B by A' },
  3: { kaR:'—', kaW:'B',   aclR:'A|B', aclW:'B',   kbR:'—',   kbW:'B',   kbRead:false, label:'Write A by B; read/write ACCESS by AB; write ACCESS by B; write B by B' },
  4: { kaR:'—', kaW:'B',   aclR:'A|B', aclW:'—',   kbR:'—',   kbW:'B',   kbRead:false, label:'Write A by B; read ACCESS by AB; write B by B' },
  5: { kaR:'—', kaW:'—',   aclR:'A|B', aclW:'B',   kbR:'—',   kbW:'—',   kbRead:false, label:'Read ACCESS by AB; write ACCESS by B' },
  6: { kaR:'—', kaW:'—',   aclR:'A|B', aclW:'—',   kbR:'—',   kbW:'—',   kbRead:false, label:'Read ACCESS by AB' },
  7: { kaR:'—', kaW:'—',   aclR:'A|B', aclW:'—',   kbR:'—',   kbW:'—',   kbRead:false, label:'Read ACCESS by AB' },
};

// ── VALUE BLOCK (cmdhfmf.c mfc_value, line 554) ──
function isVal(b) {
  const a=leU32(b,0), ai=leU32(b,4), bv=leU32(b,8);
  return (a===bv)&&(a===(~ai>>>0))&&(b[12]===((~b[13])&0xff))&&(b[14]===((~b[15])&0xff));
}
function valOf(b)     { return leI32(b,0); }
function leU32(b,o)   { return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0; }
function leI32(b,o)   { return  b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24); }
function bccOk(d)     { return (d[0]^d[1]^d[2]^d[3])===d[4]; }

// MAD AID database — optionally loaded from ./mad.json at startup
const MAD_DB = {};
let madDBReady = false;

fetch('./mad.json')
  .then(r => r.ok ? r.json() : Promise.reject(r.status))
  .then(data => {
    if (Array.isArray(data)) {
      data.forEach(e => {
        const m = (e.mad || '').replace(/^0x/i, '').toUpperCase().padStart(4, '0');
        if (!m) return;
        const app = (e.application || '').trim();
        const co  = (e.company || '').trim();
        MAD_DB[m] = app && co ? app + ' [' + co + ']' : (app || co);
      });
    } else {
      Object.assign(MAD_DB, data);
    }
    madDBReady = true;
    console.log('MFView: mad.json loaded —', Object.keys(MAD_DB).length, 'entries');
  })
  .catch(() => { /* no mad.json — silent */ });

// DESFire / ISO 7816 AID database — loaded from ./aidlist.json at startup
// 406 entries from iceman's aidlist.json
const AID_DB = {};
let aidDBReady = false;

fetch('./aidlist.json')
  .then(r => r.ok ? r.json() : Promise.reject(r.status))
  .then(data => {
    if (Array.isArray(data)) {
      data.forEach(e => {
        const aid = (e.AID || '').toUpperCase().replace(/\s/g, '');
        if (!aid) return;
        AID_DB[aid] = {
          name:    e.Name        || '',
          vendor:  e.Vendor      || '',
          country: e.Country     || '',
          desc:    e.Description || '',
        };
      });
    }
    aidDBReady = true;
    console.log('MFView: aidlist.json loaded —', Object.keys(AID_DB).length, 'entries');
  })
  .catch(() => { /* no aidlist.json — silent */ });

// lookupAID / desfireAidName — reserved for DESFire reading (future)
function lookupAID(hexStr) {
  return AID_DB[(hexStr || '').toUpperCase().replace(/\s/g, '')] || null;
}

// Admin AIDs 0x0000-0x0005 (aid_admin[] from mad.c)
const MAD_ADMIN = ['free', 'defect', 'reserved', 'additional directory info', 'card holder info', 'not applicable'];
const MAD_ADMIN_MAX = 5;

// DESFire AID list — 3-byte AIDs
const DESFIRE_AIDS = {
  'D27600008501': 'NDEF (NFC Forum Type 4)',
  'D27600002545': 'EMV Contactless (PayPass/PayWave)',
  '000000':       'PICC master file',
  'FFFFFF':       'Unallocated',
  'A00000':       'EMV / ISO payment',
  'A10000':       'Loyalty / transit',
};

// ── IC MANUFACTURER TABLE ──
// From cmdhf14a.c manufactureMapping[] — ISO/IEC JTC1/SC17 SD5 register of IC manufacturers.
// UID byte 0 identifies the chip manufacturer.
const MFR_TABLE = {
  0x01:'Motorola UK',
  0x02:'ST Microelectronics SA France',
  0x03:'Hitachi, Ltd Japan',
  0x04:'NXP Semiconductors Germany',
  0x05:'Infineon Technologies AG Germany',
  0x06:'Cylink USA',
  0x07:'Texas Instrument France',
  0x08:'Fujitsu Limited Japan',
  0x09:'Matsushita Electronics Corporation Japan',
  0x0A:'NEC Japan',
  0x0B:'Oki Electric Industry Co. Ltd Japan',
  0x0C:'Toshiba Corp. Japan',
  0x0D:'Mitsubishi Electric Corp. Japan',
  0x0E:'Samsung Electronics Co. Ltd Korea',
  0x0F:'Hynix / Hyundai Korea',
  0x10:'LG-Semiconductors Co. Ltd Korea',
  0x11:'Emosyn-EM Microelectronics USA',
  0x12:'Wisekey Semiconductors France',
  0x13:'ORGA Kartensysteme GmbH Germany',
  0x14:'SHARP Corporation Japan',
  0x15:'ATMEL France',
  0x16:'EM Microelectronic-Marin SA Switzerland',
  0x17:'SMARTRAC TECHNOLOGY GmbH Germany',
  0x18:'ZMD AG Germany',
  0x19:'XICOR, Inc. USA',
  0x1A:'Sony Corporation Japan',
  0x1B:'Malaysia Microelectronic Solutions Sdn. Bhd Malaysia',
  0x1C:'Emosyn USA',
  0x1D:'Shanghai Fudan Microelectronics Co. Ltd. China',
  0x1E:'Magellan Technology Pty Limited Australia',
  0x1F:'Melexis NV BO Switzerland',
  0x20:'Renesas Technology Corp. Japan',
  0x21:'TAGSYS France',
  0x22:'Transcore USA',
  0x23:'Shanghai Belling Corp. Ltd. China',
  0x24:'Masktech Germany GmbH Germany',
  0x25:'Innovision Research and Technology Plc UK',
  0x26:'Hitachi ULSI Systems Co., Ltd. Japan',
  0x27:'Yubico AB Sweden',
  0x28:'Ricoh Japan',
  0x29:'ASK France',
  0x2A:'Unicore Microsystems, LLC Russian Federation',
  0x2B:'Dallas Semiconductor/Maxim USA',
  0x2C:'Impinj, Inc. USA',
  0x2D:'RightPlug Alliance USA',
  0x2E:'Broadcom Corporation USA',
  0x2F:'MStar Semiconductor Inc Taiwan',
  0x30:'BeeDar Technology Inc. Taiwan',
  0x31:'RFIDsec Denmark',
  0x32:'Schweizer Electronic AG Germany',
  0x33:'AMIC Technology Corp Taiwan',
  0x34:'Mikron JSC Russia',
  0x35:'Fraunhofer Institute for Photonic Microsystems Germany',
  0x36:'IDS Microchip AG Switzerland',
  0x37:'Kovio USA',
  0x38:'HMT Microelectronic Ltd Switzerland',
  0x39:'Silicon Craft Technology Thailand',
  0x3A:'Advanced Film Device Inc. Japan',
  0x3B:'Nitecrest Ltd UK',
  0x3C:'Verayo Inc. USA',
  0x3D:'HID Global USA',
  0x3E:'Productivity Engineering GmbH Germany',
  0x3F:'Austriamicrosystems AG Austria',
  0x40:'Gemalto SA France',
  0x41:'Renesas Electronics Corporation Japan',
  0x42:'3Alogics Inc Korea',
  0x43:'Top TroniQ Asia Limited Hong Kong',
  0x44:'Gentag Inc. USA',
  0x45:'Invengo Information Technology Co.Ltd China',
  0x46:'Guangzhou Sysur Microelectronics, Inc China',
  0x47:'CEITEC S.A. Brazil',
  0x48:'Shanghai Quanray Electronics Co. Ltd. China',
  0x49:'Media Tek Inc Taiwan',
  0x4A:'Angstrem JSC Russia',
  0x4B:'Celisic Semiconductor (Hong Kong) Limited',
  0x4C:'LEGIC Identsystems AG Switzerland',
  0x4D:'Balluff GmbH Germany',
  0x4E:'Oberthur Technologies France',
  0x4F:'Silterra Malaysia Sdn. Bhd. Malaysia',
  0x50:'Presto Engineering Denmark',
  0x51:'Giesecke & Devrient GmbH Germany',
  0x52:'Shenzhen China Vision Microelectronics Co., Ltd. China',
  0x53:'Shanghai Feiju Microelectronics Co. Ltd. China',
  0x54:'Intel Corporation USA',
  0x55:'Microsensys GmbH Germany',
  0x56:'Sonix Technology Co., Ltd. Taiwan',
  0x57:'Qualcomm Technologies Inc USA',
  0x58:'Realtek Semiconductor Corp Taiwan',
  0x59:'Freevision Technologies Co. Ltd China',
  0x5A:'Giantec Semiconductor Inc. China',
  0x5B:'JSC Angstrem-T Russia',
  0x5C:'STARCHIP France',
  0x5D:'SPIRTECH France',
  0x5E:'GANTNER Electronic GmbH Austria',
  0x5F:'Nordic Semiconductor Norway',
  0x60:'Verisiti Inc USA',
  0x61:'Wearlinks Technology Inc. China',
  0x62:'Userstar Information Systems Co., Ltd Taiwan',
  0x63:'Pragmatic Printing Ltd. UK',
  0x65:'Tendyron Corporation China',
  0x66:'MUTO Smart Co., Ltd. Korea',
  0x67:'ON Semiconductor USA',
  0x68:'TUBITAK BILGEM Turkey',
  0x69:'Huada Semiconductor Co., Ltd China',
  0x6A:'SEVENEY France',
  0x6B:'THALES DIS Design Services SAS France',
  0x6C:'Wisesec Ltd Israel',
  0x6D:'LTD NM-Teh Russia',
  0x70:'ifm electronic gmbh Germany',
  0x71:'Sichuan Kiloway Technologies Co., Ltd. China',
  0x72:'Ford Motor Company US',
  0x73:'Beijing Tsingteng MicroSystem Co.,Ltd China',
  0x74:'Huada EverCore Co., Ltd China',
  0x75:'Smartchip Microelectronics Corporation Taiwan',
  0x76:'Tongxin Microelectronics Co., Ltd. China',
  0x77:'Ningbo IOT Microelectronics Co Ltd China',
  0x78:'AU Optronics Taiwan',
  0x79:'CUBIC USA',
  0x7A:'Abbott Diabetes Care USA',
  0x7B:'Shenzen Nation RFID Technology Co Ltd China',
  0x7C:'DB HiTek Co Ltd Korea',
  0x7D:'SATO Vicinity Australia',
  0x7E:'Holtek Taiwan',
  0x96:'Trovan Limited Isle of Man',
};

// ── SAK → CARD TYPE LABEL ──
// Derived from detect_nxp_card_print() in cmdhf14a.c (NXP AN10833/AN10834)
// Used to add a hint to the SAK byte in block 0's decoded note.
const SAK_TYPES = {
  0x00:'MIFARE Ultralight / NTAG',
  0x01:'MIFARE TNP3xxx',
  0x08:'MIFARE Classic 1K',
  0x09:'MIFARE Mini 0.3K',
  0x10:'MIFARE Plus 2K SL2',
  0x11:'MIFARE Plus 4K SL2',
  0x18:'MIFARE Classic 4K',
  0x19:'MIFARE Classic 2K',
  0x20:'MIFARE Plus SL0/SL3 or DESFire',
  0x28:'SmartMX with MIFARE Classic 1K',
  0x38:'SmartMX with MIFARE Classic 4K',
  0x88:'Infineon MIFARE Classic 1K',
  0x98:'Gemplus MPCOS',
};

function getMfrName(uidByte0) {
  return MFR_TABLE[uidByte0] || null;
}

function getSakType(sak) {
  return SAK_TYPES[sak] || null;
}

// MAD AID lookup — reads LE uint16 from dump bytes [lo, hi]
// Returns { aidNum, aidStr, name, isAdmin, adminLabel }
function parseMadAid(lo, hi) {
  const aidNum = (hi << 8) | lo;
  const aidStr = byteHex(hi).toUpperCase() + byteHex(lo).toUpperCase();
  if (aidNum <= MAD_ADMIN_MAX) {
    return { aidNum, aidStr, name: null, isAdmin: true, adminLabel: MAD_ADMIN[aidNum] };
  }
  return { aidNum, aidStr, name: MAD_DB[aidStr] || null, isAdmin: false };
}

// DESFire AID lookup
function desfireAidName(aidHex) { // reserved for DESFire reading (future)
  return DESFIRE_AIDS[aidHex.toUpperCase()] || null;
}

// ── MAD STRUCT PARSERS ──
// Struct layout from mad.h:
//   byte 16: MAD1 CRC, byte 17: info byte (lower 6 bits = card publisher sector)
//   bytes 18-47: 15 x LE uint16 AIDs (sectors 1-15)
//   byte 1024: MAD2 CRC, byte 1025: info, bytes 1026+: 23 x LE uint16 AIDs (sectors 17-39)

function parseMadV1(d) {
  if (d.length < 48) return { apps: [], crc: 0, info: 0 };
  const crc  = d[16];
  const info = d[17] & 0x3F;
  const apps = [];
  let prevAidNum = 0xFFFFFFFF;
  for (let i = 0; i < 15; i++) {
    const off = 18 + i * 2;
    if (off + 1 >= d.length) break;
    const entry = parseMadAid(d[off], d[off + 1]);
    entry.sector = i + 1;
    entry.isPublisher = (i + 1 === info);
    entry.isContinuation = (!entry.isAdmin && entry.aidNum === prevAidNum);
    if (!entry.isContinuation) prevAidNum = entry.aidNum;
    apps.push(entry);
  }
  return { apps, crc, info };
}

function parseMadV2(d) {
  const base = 64 * 16; // block 64 = byte 1024
  if (d.length < base + 48) return null;
  const crc  = d[base];
  const info = d[base + 1] & 0x3F;
  const apps = [];
  let prevAidNum = 0xFFFFFFFF;
  for (let i = 0; i < 23; i++) {
    const off = base + 2 + i * 2;
    if (off + 1 >= d.length) break;
    const entry = parseMadAid(d[off], d[off + 1]);
    entry.sector = i + 17;
    entry.isPublisher = (i + 17 === info);
    entry.isContinuation = (!entry.isAdmin && entry.aidNum === prevAidNum);
    if (!entry.isContinuation) prevAidNum = entry.aidNum;
    apps.push(entry);
  }
  return { apps, crc, info };
}

function hasMadKey(d) {
  if (d.length < 64) return false;
  const st = d.slice(48, 54);
  const m1 = [0xA0,0xA1,0xA2,0xA3,0xA4,0xA5];
  const m2 = [0xD3,0xF7,0xD3,0xF7,0xD3,0xF7];
  return m1.every((v,i)=>st[i]===v) || m2.every((v,i)=>st[i]===v);
}

// ── STATE ──
let dump   = null;
let fname  = '';
let fext   = '';   // loaded file extension — used to disable matching save button
let card   = null;
let curSec = 0;
let opts   = { kc:true, st:true, mad:true, val:true };
let vm     = 'all';

// ── FILE LOADING ──
function triggerOpen() { document.getElementById('fi').click(); }

function loadFile(e) {
  const f = e.target.files[0];
  if (f) readDump(f);
  e.target.value = '';
}

function onDO(e) { e.preventDefault(); document.getElementById('dz').classList.add('drag'); }
function onDL()  { document.getElementById('dz').classList.remove('drag'); }
function onDrop(e) {
  e.preventDefault(); onDL();
  if (e.dataTransfer.files[0]) readDump(e.dataTransfer.files[0]);
}

function readDump(f) {
  fname = f.name;
  fext  = f.name.split('.').pop().toLowerCase();
  const ext = fext;
  const reader = new FileReader();
  if (ext === 'eml') {
    reader.onload = ev => parseEML(ev.target.result);
    reader.readAsText(f);
  } else if (ext === 'json') {
    reader.onload = ev => parseJSON(ev.target.result);
    reader.readAsText(f);
  } else {
    reader.onload = ev => parseBIN(new Uint8Array(ev.target.result));
    reader.readAsArrayBuffer(f);
  }
}

function parseBIN(bytes) { dump = bytes; onLoaded(); }

function parseEML(text) {
  const lines = text.split('\n').map(l=>l.trim()).filter(l=>/^[0-9a-fA-F]+$/.test(l) && l.length%2===0);
  if (!lines.length) { setSt('No valid EML data found'); return; }
  // Detect block size: 32 chars = 16 bytes (Classic/Plus) or 8 chars = 4 bytes (UL)
  const lineLen = lines[0].length;
  const bsize = lineLen / 2;
  const arr = new Uint8Array(lines.length * bsize);
  lines.forEach((l,i) => { for(let b=0;b<bsize;b++) arr[i*bsize+b]=parseInt(l.slice(b*2,b*2+2),16); });
  dump = arr; onLoaded();
}

function parseJSON(text) {
  let j;
  try { j = JSON.parse(text); } catch(e) { setSt('Invalid JSON: '+e.message); return; }

  // Iceman jsfCardMemory: { "blocks": { "0":"hex...", ... } }
  const blocks = j.blocks || j.Blocks;
  if (blocks && typeof blocks==='object' && !Array.isArray(blocks)) {
    const indices = Object.keys(blocks).map(Number).sort((a,b)=>a-b);
    const maxIdx  = Math.max(...indices);
    // Detect block size from first entry
    const firstVal = Object.values(blocks)[0];
    const hexStr   = typeof firstVal==='string' ? firstVal.replace(/\s/g,'') : '';
    const bsize    = hexStr.length > 8 ? 16 : 4; // 32 chars → 16B (Classic), 8 chars → 4B (UL)
    const arr = new Uint8Array((maxIdx + 1) * bsize);
    for (const [k, v] of Object.entries(blocks)) {
      const bi  = parseInt(k);
      const hex = typeof v==='string' ? v.replace(/\s/g,'') : (Array.isArray(v) ? v.map(x=>byteHex(x)).join('') : '');
      for (let b=0;b<bsize&&b*2+2<=hex.length;b++) arr[bi*bsize+b]=parseInt(hex.slice(b*2,b*2+2),16);
    }
    dump = arr; onLoaded(); return;
  }
  if (Array.isArray(j)) {
    const firstHex = typeof j[0]==='string' ? j[0].replace(/\s/g,'') : '';
    const bsize = firstHex.length > 8 ? 16 : 4;
    const arr = new Uint8Array(j.length * bsize);
    j.forEach((row,i) => {
      const hex = typeof row==='string' ? row.replace(/\s/g,'') : (Array.isArray(row) ? row.map(x=>byteHex(x)).join('') : '');
      for(let b=0;b<bsize;b++) arr[i*bsize+b]=parseInt(hex.slice(b*2,b*2+2)||'00',16);
    });
    dump = arr; onLoaded(); return;
  }
  setSt('JSON format not recognised');
}

// ── DETECT CARD TYPE ──
function detectCard(bytes) {
  const len = bytes.length;

  // Classic / Plus: 16-byte blocks
  if (len % 16 === 0) {
    // Exact size match first
    if (CARD_DB[len]) return { ...CARD_DB[len] };

    // MF Plus 2K/4K share the same sizes as Classic 2K/4K and can't be told apart
    // from dump data alone, so they render through the Classic entries below.
    const blks = len / 16;
    if (blks <= 20)  return { ...CARD_DB[320] };
    if (blks <= 64)  return { ...CARD_DB[1024] };
    if (blks <= 72)  return { ...CARD_DB[1152] };
    if (blks <= 128) return { ...CARD_DB[2048] };
    if (blks <= 256) return { ...CARD_DB[4096] };
  }

  // Ultralight: 4-byte pages (not divisible by 16 but by 4)
  if (len % 4 === 0 && len % 16 !== 0) {
    return detectMFU(len);
  }

  // MFU dump with prefix header (old format: 48-byte prefix + data)
  if (len > 48 && (len - 48) % 4 === 0) {
    const t = detectMFU(len - 48);
    return { ...t, hasPrefix: true, prefixLen: 48 };
  }
  // New MFU dump format prefix varies — try common prefix lengths
  for (const prefix of [56, 64, 72]) {
    if (len > prefix && (len - prefix) % 4 === 0) {
      const t = detectMFU(len - prefix);
      return { ...t, hasPrefix: true, prefixLen: prefix };
    }
  }

  return null;
}

function onLoaded() {
  card = detectCard(dump);
  if (!card) { setSt('Unknown dump size: ' + dump.length + ' bytes'); return; }

  const uid = card.family === 'ultralight' ? mfuUidStr() : mfcUidStr();
  document.getElementById('p-type').textContent = card.short || card.name;
  document.getElementById('p-uid').textContent  = uid;
  document.getElementById('p-sec').textContent  = card.family==='ultralight' ? card.pages + ' pg' : card.sectors;
  document.getElementById('p-blk').textContent  = card.family==='ultralight' ? card.pages : card.blocks;
  document.getElementById('p-sz').textContent   = dump.length + ' B';
  document.getElementById('st-r').textContent   = uid;

  renderCardInfo();
  renderSidebar();
  render();

  document.getElementById('dz').classList.add('gone');
  document.getElementById('dv').classList.add('on');
  document.getElementById('jnav').classList.add('on');
  document.getElementById('btn-savebin').disabled  = (fext === 'bin');
  document.getElementById('btn-savejson').disabled = (fext === 'json');
  setSt(fname + ' — ' + card.name + ' · ' + dump.length + ' bytes');
}

function closeDump() {
  dump = null; card = null; curSec = 0;
  ['p-type','p-uid','p-sec','p-blk','p-sz'].forEach(id=>{ document.getElementById(id).textContent='--'; });
  document.getElementById('st-r').textContent = '';
  document.getElementById('dz').classList.remove('gone');
  document.getElementById('dv').classList.remove('on');
  document.getElementById('jnav').classList.remove('on');
  document.getElementById('btn-savebin').disabled  = true;
  document.getElementById('btn-savejson').disabled = true;
  document.getElementById('db').innerHTML = '';
  document.getElementById('ci').innerHTML = '';
  document.getElementById('snav').innerHTML = '';
  document.getElementById('ms-l').innerHTML = '';
  document.getElementById('sb-cnt').textContent = '0';
  setSt('Ready — open a dump file (.bin / .eml / .json)');
}

// ── UID HELPERS ──
function mfcUidStr() {
  if (!dump || dump.length < 4) return '--';
  return [dump[0],dump[1],dump[2],dump[3]].map(b=>byteHex(b).toUpperCase()).join(':');
}
function mfuUidStr() {
  if (!dump || dump.length < 8) return '--';
  const data = card.hasPrefix ? dump.slice(card.prefixLen) : dump;
  // MFU UID: 3 bytes page0 + 1 byte page1 (CT) + 3 bytes page1(1-3) → UID0-2, CT, UID3-6
  // Pages 0-1-2 contain the 7-byte UID with cascade tag byte at data[3]
  return [data[0],data[1],data[2],data[4],data[5],data[6],data[7]]
    .map(b=>byteHex(b).toUpperCase()).join(':');
}

// ── CARD INFO BANNER ──
function renderCardInfo() {
  const el = document.getElementById('ci');
  if (card.family === 'ultralight') {
    renderCardInfoMFU(el);
  } else {
    renderCardInfoMFC(el);
  }
}

function renderCardInfoMFC() {
  const bcc     = bccOk(dump);
  const sak     = byteHex(dump[5]).toUpperCase();
  const atqa    = byteHex(dump[6]).toUpperCase() + ' ' + byteHex(dump[7]).toUpperCase();
  const mfr     = getMfrName(dump[0]);
  const sakType = getSakType(dump[5]);

  const mfrRow     = mfr ? '<div class="ci-i"><span class="ci-l">Mfr</span><span class="ci-v mfr">' + mfr + '</span></div>' : '';
  const ev1Row     = card.ev1 ? '<div class="ci-i"><span class="ci-l">Note</span><span class="ci-v" style="color:#3ecfcf">EV1 &#8212; blocks 64&#8211;71 are NXP signature area</span></div>' : '';

  document.getElementById('ci').innerHTML = `
    <div class="ci-i"><span class="ci-l">UID</span><span class="ci-v u">${mfcUidStr()}</span></div>
    <div class="ci-i"><span class="ci-l">BCC</span><span class="ci-v ${bcc?'a':''}">${byteHex(dump[4]).toUpperCase()} ${bcc?'&#10003;':'&#10007; invalid'}</span></div>
    <div class="ci-i"><span class="ci-l">SAK</span><span class="ci-v sak">${sak}${sakType?' <span class="ci-sak-type">('+sakType+')</span>':''}</span></div>
    <div class="ci-i"><span class="ci-l">ATQA</span><span class="ci-v atqa">${atqa}</span></div>
    <div class="ci-i"><span class="ci-l">Type</span><span class="ci-v a">${card.name}</span></div>
    ${mfrRow}${ev1Row}
  `;
}

function renderCardInfoMFU() {
  const data = card.hasPrefix ? dump.slice(card.prefixLen) : dump;
  document.getElementById('ci').innerHTML = `
    <div class="ci-i"><span class="ci-l">UID</span><span class="ci-v u">${mfuUidStr()}</span></div>
    <div class="ci-i"><span class="ci-l">BCC0</span><span class="ci-v">${byteHex(data[3]).toUpperCase()}</span></div>
    <div class="ci-i"><span class="ci-l">BCC1</span><span class="ci-v">${byteHex(data[8]).toUpperCase()}</span></div>
    <div class="ci-i"><span class="ci-l">Type</span><span class="ci-v a">${card.name}</span></div>
    <div class="ci-i"><span class="ci-l">Pages</span><span class="ci-v">${card.pages}</span></div>
    <div class="ci-i"><span class="ci-l">Size</span><span class="ci-v">${card.pages * 4} bytes user data</span></div>
  `;
}

// ── SIDEBAR ──
function renderSidebar() {
  const nav = document.getElementById('snav');
  const msl = document.getElementById('ms-l');
  nav.innerHTML = ''; msl.innerHTML = '';

  if (card.family === 'ultralight') {
    renderSidebarMFU(nav, msl);
  } else {
    renderSidebarMFC(nav, msl);
  }
}

function renderSidebarMFC(nav, msl) {
  document.getElementById('sb-cnt').textContent = card.sectors;
  for (let s = 0; s < card.sectors; s++) {
    const stb = firstBlk(s) + blksPerSec(s) - 1;
    const sd  = dump.slice(stb*BLOCK_MFC, stb*BLOCK_MFC+BLOCK_MFC);
    const ka  = hexStr(sd, 0, 6).toUpperCase();
    const kb  = hexStr(sd,10, 6).toUpperCase();
    const isMad = s===0 && hasMadKey(dump);
    const acl = parseACL(sd[6], sd[7], sd[8]);

    const li = document.createElement('li');
    li.className='si'; li.dataset.s=s;
    li.innerHTML=`<div class="si-bar"></div>
      <div class="si-body">
        <div class="si-num">Sector ${s} &middot; blk ${firstBlk(s)}&ndash;${stb}</div>
        <div class="si-keys">A:${ka} B:${kb}</div>
      </div>
      <span class="si-bdg ${isMad?'c':'g'}">${isMad?'MAD':'S'+String(s).padStart(2,'0')}</span>`;
    li.addEventListener('click',()=>jumpToSector(s));
    nav.appendChild(li);

    const di=document.createElement('div');
    di.className='ms-i'; di.dataset.s=s;
    di.innerHTML=`<div class="ms-bar"></div>
      <div class="ms-body">
        <div class="ms-meta">Sector ${s} &middot; blk ${firstBlk(s)}&ndash;${stb}${!acl.valid?' &middot; &#9888; bad ACL':''}</div>
        <div class="ms-prev">A:${ka} B:${kb}</div>
      </div>`;
    di.addEventListener('click',()=>{ jumpToSector(s); closeMS(); });
    msl.appendChild(di);
  }
}

function renderSidebarMFU(nav, msl) {
  document.getElementById('sb-cnt').textContent = card.pages;
  const data = card.hasPrefix ? dump.slice(card.prefixLen) : dump;
  // Show every 8 pages as a nav item
  const step = 8;
  for (let p = 0; p < card.pages; p += step) {
    const end = Math.min(p + step - 1, card.pages - 1);
    const li = document.createElement('li');
    li.className = 'si'; li.dataset.p = p;
    const preview = hexStr(data, p*4, 4).toUpperCase();
    li.innerHTML = `<div class="si-bar"></div>
      <div class="si-body">
        <div class="si-num">Pages ${p}&ndash;${end}</div>
        <div class="si-keys">${preview}</div>
      </div>`;
    li.addEventListener('click', ()=>jumpToPage(p));
    nav.appendChild(li);

    const di = document.createElement('div');
    di.className = 'ms-i';
    di.innerHTML = `<div class="ms-bar"></div>
      <div class="ms-body">
        <div class="ms-meta">Pages ${p}&ndash;${end}</div>
        <div class="ms-prev">${preview}</div>
      </div>`;
    di.addEventListener('click', ()=>{ jumpToPage(p); closeMS(); });
    msl.appendChild(di);
  }
}

// ── MAIN RENDER ──
function render() {
  const db = document.getElementById('db');
  db.innerHTML = '';
  if (card.family === 'ultralight') {
    renderMFU(db);
  } else {
    renderMFC(db);
  }
}

// ── RENDER CLASSIC / PLUS ──
function renderMFC(db) {
  const frag = document.createDocumentFragment();
  for (let s = 0; s < card.sectors; s++) frag.appendChild(buildSector(s));
  if (opts.mad && hasMadKey(dump)) {
    const m = buildMADSection();
    if (m) frag.appendChild(m);
  }
  // Show DESFire AID reference when SAK indicates DESFire or MF Plus SL3
  if (dump[5] === 0x20 || dump[5] === 0x28) {
    const a = buildAIDSection();
    if (a) frag.appendChild(a);
  }
  db.appendChild(frag);
}

function buildSector(s) {
  const fb  = firstBlk(s);
  const nb  = blksPerSec(s);
  const stb = fb + nb - 1;
  const sd  = dump.slice(stb*BLOCK_MFC, stb*BLOCK_MFC+BLOCK_MFC);
  const acl = parseACL(sd[6], sd[7], sd[8]);
  const isMad = s===0 && hasMadKey(dump);

  const el = document.createElement('div');
  el.className='sc'; el.id='sec-'+s;

  const hdr = document.createElement('div');
  hdr.className='sc-hdr';
  hdr.innerHTML=`<span class="sc-num">Sector ${s}</span>
    <span style="color:var(--text-dim)">blocks ${fb}&ndash;${stb}</span>
    ${isMad?'<span class="sc-bdg c">MAD</span>':''}
    ${!acl.valid?'<span class="sc-bdg e">BAD ACL</span>':''}
    <span class="sc-chev">&#9662;</span>`;
  hdr.addEventListener('click',()=>el.classList.toggle('coll'));
  el.appendChild(hdr);

  const body = document.createElement('div');
  body.className='sc-body';

  const ch = document.createElement('div');
  ch.className='bch';
  ch.innerHTML='<span class="bch-b">blk</span><span class="bch-h">hex</span><span class="bch-a">ascii</span><span class="bch-n">decoded</span>';
  body.appendChild(ch);

  for (let b = fb; b <= stb; b++) {
    const bytes = dump.slice(b*BLOCK_MFC, b*BLOCK_MFC+BLOCK_MFC);
    const isEV1 = card.ev1 && b >= 64;
    const rows  = buildBlockRow(b, bytes, s, b===stb, b===0, isEV1, acl);
    if (Array.isArray(rows)) rows.forEach(r=>body.appendChild(r));
    else body.appendChild(rows);
  }

  if (opts.st && vm!=='data') body.appendChild(buildSTDec(sd, acl, s, stb));
  el.appendChild(body);
  return el;
}

// ── BLOCK ROW (Classic / Plus) ──
function buildBlockRow(b, bytes, s, isST, isMfr, isEV1, acl) {
  const isValue = !isST && !isMfr && !isEV1 && opts.val && isVal(bytes);
  const row = document.createElement('div');
  let cls = 'br';
  if (isMfr)       cls += ' mfr';
  else if (isEV1)  cls += ' ev1';
  else if (isValue) cls += ' val';
  else if (isST)   cls += ' st';
  row.className = cls;

  const hexHtml = isMfr    ? renderMfrHex(bytes)
                : isST     ? renderSTHex(bytes)
                : isValue  ? renderValHex(bytes)
                : renderDataHex(bytes);

  const note = isMfr
    ? (() => {
        const mfr = getMfrName(bytes[0]);
        const sakType = getSakType(bytes[5]);
        return 'UID: '    + hexStr(bytes,0,4).toUpperCase()
          + ' \u00b7 BCC: ' + byteHex(bytes[4]).toUpperCase() + ' ' + (bccOk(dump)?'\u2713':'\u2717 invalid')
          + ' \u00b7 SAK: ' + byteHex(bytes[5]).toUpperCase() + (sakType ? ' (' + sakType + ')' : '')
          + ' \u00b7 ATQA: '+ byteHex(bytes[6]).toUpperCase() + ' ' + byteHex(bytes[7]).toUpperCase()
          + (mfr ? ' \u00b7 Mfr: ' + mfr : '');
      })()
    : isST
    ? 'Key A \u00b7 ACL ('
      + byteHex(bytes[6]).toUpperCase()+' '
      + byteHex(bytes[7]).toUpperCase()+' '
      + byteHex(bytes[8]).toUpperCase()
      + ') \u00b7 GPB: ' + byteHex(bytes[9]).toUpperCase() + ' \u00b7 Key B'
    : isEV1   ? 'NXP EV1 signature block'
    : isValue ? 'Value: ' + valOf(bytes) + ' \u00b7 addr: ' + bytes[12]
    : '';

  row.innerHTML =
    '<span class="br-b">' + b + '</span>' +
    '<span class="br-h">' + hexHtml + '</span>' +
    '<span class="br-a">' + escHtml(asciiOf(bytes)) + '</span>' +
    '<span class="br-n">' + escHtml(note) + '</span>';

  if (isValue) {
    const v  = valOf(bytes);
    const vd = document.createElement('div');
    vd.className = 'vd';
    vd.innerHTML = '<span class="vd-l">value</span><span class="vd-v">'+v+'</span>'
      + '<span class="vd-l">hex</span><span class="vd-v">0x'+(v>>>0).toString(16).toUpperCase().padStart(8,'0')+'</span>'
      + '<span class="vd-l">addr</span><span class="vd-a">'+bytes[12]+'</span>';
    return [row, vd];
  }
  return row;
}

// ── HEX RENDERERS (Classic / Plus) ──

function renderMfrHex(b) {
  // Block 0 layout:
  // [0-3] UID — RED   [4] BCC — YELLOW   [5] SAK — ORANGE
  // [6-7] ATQA — AMBER   [8-15] IC manufacturer data — dim purple
  let h = '';
  for (let i=0;i<16;i++) {
    if (i) h+=' ';
    const x = byteHex(b[i]).toUpperCase();
    if      (i < 4)  h += '<span class="b-u">'    + x + '</span>'; // UID
    else if (i===4)  h += '<span class="b-bcc">'   + x + '</span>'; // BCC
    else if (i===5)  h += '<span class="b-sak">'   + x + '</span>'; // SAK
    else if (i < 8)  h += '<span class="b-atqa">'  + x + '</span>'; // ATQA
    else             h += '<span class="b-mfr">'   + x + '</span>'; // Mfr data
  }
  return h;
}

function renderSTHex(b) {
  if (!opts.kc) return renderDataHex(b);
  let h = '';
  for (let i=0;i<16;i++) {
    if (i) h+=' ';
    const x = byteHex(b[i]).toUpperCase();
    if      (i < 6)  h += '<span class="b-k">' + x + '</span>'; // Key A — BRIGHT_GREEN
    else if (i < 9)  h += '<span class="b-c">' + x + '</span>'; // ACL   — MAGENTA
    else if (i===9)  h += '<span class="b-g">' + x + '</span>'; // GPB
    else             h += '<span class="b-b">' + x + '</span>'; // Key B — GREEN
  }
  return h;
}

function renderValHex(b) {
  let h='';
  for(let i=0;i<16;i++){if(i)h+=' ';h+='<span class="b-v">'+byteHex(b[i]).toUpperCase()+'</span>';}
  return h;
}

function renderDataHex(b) {
  let h='';
  for(let i=0;i<16;i++){
    if(i)h+=' ';
    const x=byteHex(b[i]).toUpperCase();
    h+=b[i]===0?'<span class="b-0">'+x+'</span>':'<span class="b-d">'+x+'</span>';
  }
  return h;
}

// ── SECTOR TRAILER DECODER ──
// Mirrors decode_print_st() from cmdhfmf.c

function buildSTDec(sd, acl, s, stb) {
  const wrap = document.createElement('div');
  wrap.className = 'std';
  const ka     = hexStr(sd, 0, 6).toUpperCase();
  const kb     = hexStr(sd,10, 6).toUpperCase();
  const gpb    = byteHex(sd[9]).toUpperCase();
  const aclHex = [sd[6],sd[7],sd[8]].map(b=>byteHex(b).toUpperCase()).join(' ');

  let html = '<div class="std-t">Sector trailer decoder &mdash; sector '+s+' / block '+stb+'</div>';
  html += '<div class="std-keys">'
    + '<div class="std-k"><div class="std-kl">Key A</div><div class="std-kv ka">'+ka+'</div></div>'
    + '<div class="std-k"><div class="std-kl">ACR (ACL bytes)</div><div class="std-kv acl">'+aclHex+'</div></div>'
    + '<div class="std-k"><div class="std-kl">User / GPB</div><div class="std-kv gpb">'+gpb+'</div></div>'
    + '<div class="std-k"><div class="std-kl">Key B</div><div class="std-kv kb">'+kb+'</div></div>'
    + '</div>';

  if (!acl.valid) html += '<div class="invalid-acl">&#9888; Invalid access conditions &mdash; inverted bits do not match.</div>';

  const nb    = blksPerSec(s);
  const fb    = firstBlk(s);
  const blinc = nb > 4 ? 5 : 1;

  html += '<table class="acl-t"><thead><tr><th>#</th><th>C1 C2 C3</th><th>Read</th><th>Write</th><th>Inc</th><th>Dec/Restore</th><th>Access rights</th></tr></thead><tbody>';

  let kbReadable=false, bln=fb;
  for (let i=0;i<4;i++) {
    const c1=acl.c1[i], c2=acl.c2[i], c3=acl.c3[i];
    const key=acKey(c1,c2,c3);
    if (i===3) {
      const st=ST_AC[key]||{kaR:'?',kaW:'?',aclR:'?',aclW:'?',kbR:'?',kbW:'?',kbRead:false,label:'Unknown'};
      if(st.kbRead) kbReadable=true;
      const pKaW=st.kaW==='—'?'p-no':'p-rw', pKbW=st.kbW==='—'?'p-no':'p-rw';
      html+='<tr><td>'+stb+' <span style="font-size:9px;color:var(--text-dim)">ST</span></td>'
        +'<td class="acl-bits">'+c1+' '+c2+' '+c3+'</td>'
        +'<td><span class="pill p-no">KA:'+st.kaR+'</span></td>'
        +'<td><span class="pill '+pKaW+'">KA:'+st.kaW+'</span></td>'
        +'<td><span class="pill p-no">ACL:'+st.aclR+'</span></td>'
        +'<td><span class="pill '+pKbW+'">KB:'+st.kbW+'</span></td>'
        +'<td class="acl-desc'+(st.kbRead?' acl-warn':'')+'">'+st.label+'</td></tr>';
    } else {
      const e=DATA_AC[key]||{rd:'?',wr:'?',inc:'?',dec:'?',label:'Unknown'};
      const blkLabel=(blinc>1&&i<3)?bln+'+':String(bln);
      const pRd=e.rd==='—'?'p-no':'p-ro', pWr=e.wr==='—'?'p-no':'p-rw';
      const pInc=e.inc==='—'?'p-no':'p-rw', pDec=e.dec==='—'?'p-no':'p-rw';
      html+='<tr><td>'+blkLabel+'</td>'
        +'<td class="acl-bits">'+c1+' '+c2+' '+c3+'</td>'
        +'<td><span class="pill '+pRd+'">'+e.rd+'</span></td>'
        +'<td><span class="pill '+pWr+'">'+e.wr+'</span></td>'
        +'<td><span class="pill '+pInc+'">'+e.inc+'</span></td>'
        +'<td><span class="pill '+pDec+'">'+e.dec+'</span></td>'
        +'<td class="acl-desc">'+e.label+'</td></tr>';
      bln+=blinc;
    }
  }
  html+='</tbody></table>';
  if (kbReadable) html+='<div class="keyb-warn">OBS! Key B is readable &mdash; it SHALL NOT be able to authenticate on original MFC</div>';
  wrap.innerHTML=html;
  return wrap;
}

// ── MAD SECTION ──
function buildMADSection() {
  const v1 = parseMadV1(dump);
  const v2 = (dump.length >= 1024 + 48) ? parseMadV2(dump) : null;

  if (!v1 || !v1.apps.length) return null;

  // Show all sectors including free (0000) ones — matches hf mf mad verbose output
  const v1apps = v1.apps;
  const v2apps = v2 ? v2.apps : [];

  if (!v1apps.length && !v2apps.length) return null;

  const el = document.createElement('div');
  el.className = 'mad-sec';

  const gpb    = dump[57]; // sector 0 trailer GPB byte
  const madVer = gpb & 0x03;
  const isMulti = (gpb & 0x40) !== 0;
  const hasV2   = v2apps.length > 0;

  let html = '<div class="mad-t">MIFARE Application Directory (MAD v' + (hasV2 ? '1+2' : '1') + ')</div>';

  html += '<div class="mad-meta">'
    + '<span class="mad-meta-i">GPB: <strong>' + byteHex(gpb).toUpperCase() + '</strong></span>'
    + '<span class="mad-meta-i">Version: <strong>' + madVer + '</strong></span>'
    + '<span class="mad-meta-i">' + (isMulti ? 'Multi-application card' : 'Single-application card') + '</span>'
    + (v1.info ? '<span class="mad-meta-i">Publisher sector: <strong>' + v1.info + '</strong></span>' : '')
    + '</div>';

  html += '<table class="mad-tbl"><thead><tr><th>Sector</th><th>AID</th><th>Application</th></tr></thead><tbody>';

  for (const a of v1apps) html += buildMADRow(a);

  if (hasV2) {
    html += '<tr><td colspan="3" class="mad-hdr-row">MAD v2 &mdash; sectors 17&ndash;39</td></tr>';
    for (const a of v2apps) html += buildMADRow(a);
  }

  html += '</tbody></table>';
  el.innerHTML = html;
  return el;
}

function buildMADRow(a) {
  const pubCls = a.isPublisher ? ' mad-pub' : '';
  let aidCell, nameCell;

  if (a.isAdmin) {
    aidCell  = '<td class="ah ae">' + a.aidStr + '</td>';
    nameCell = '<td class="ae">' + a.adminLabel + '</td>';
  } else if (a.isContinuation) {
    aidCell  = '<td class="ah" style="color:var(--text-dim)">' + a.aidStr + '</td>';
    nameCell = '<td class="ae">continuation</td>';
  } else if (a.name) {
    aidCell  = '<td class="ah">' + a.aidStr + '</td>';
    nameCell = '<td class="an">' + escHtml(a.name) + '</td>';
  } else {
    aidCell  = '<td class="ah">' + a.aidStr + '</td>';
    nameCell = '<td class="ae">unknown AID</td>';
  }

  return '<tr class="' + pubCls + '"><td>' + a.sector + (a.isPublisher ? ' &#9733;' : '') + '</td>' + aidCell + nameCell + '</tr>';
}

// ── DESFIRE / ISO 7816 AID SECTION ──
// Shown when SAK indicates DESFire (0x20) or MF Plus SL3 (0x28)
// Displays all entries from aidlist.json as a reference table

function buildAIDSection() {
  if (!aidDBReady || !Object.keys(AID_DB).length) return null;

  const el = document.createElement('div');
  el.className = 'mad-sec'; // reuse same styling

  let html = '<div class="mad-t">ISO 7816 / DESFire AID Reference (' + Object.keys(AID_DB).length + ' entries)</div>';
  html += '<div class="mad-meta">'
    + '<span class="mad-meta-i">SAK <strong>0x' + byteHex(dump[5]).toUpperCase() + '</strong> indicates DESFire or MIFARE Plus SL3</span>'
    + '<span class="mad-meta-i">Loaded from <strong>aidlist.json</strong></span>'
    + '</div>';

  html += '<table class="mad-tbl"><thead><tr>'
    + '<th>AID</th><th>Name</th><th>Vendor</th><th>Country</th>'
    + '</tr></thead><tbody>';

  for (const [aid, entry] of Object.entries(AID_DB)) {
    if (!entry.name) continue; // skip blank entries
    html += '<tr>'
      + '<td class="ah" style="font-size:10px">' + escHtml(aid) + '</td>'
      + '<td class="an">' + escHtml(entry.name) + '</td>'
      + '<td class="ae">' + escHtml(entry.vendor) + '</td>'
      + '<td class="ae">' + escHtml(entry.country) + '</td>'
      + '</tr>';
  }

  html += '</tbody></table>';
  el.innerHTML = html;
  return el;
}
function renderMFU(db) {
  const data   = card.hasPrefix ? dump.slice(card.prefixLen) : dump;
  const pages  = Math.floor(data.length / BLOCK_MFU);
  const frag   = document.createDocumentFragment();

  // Single card wrapper
  const el = document.createElement('div');
  el.className = 'sc'; el.id = 'sec-0';

  const hdr = document.createElement('div');
  hdr.className = 'sc-hdr';
  hdr.innerHTML = '<span class="sc-num">'+card.name+'</span>'
    + '<span style="color:var(--text-dim)">'+pages+' pages &middot; '+(pages*4)+' bytes</span>'
    + '<span class="sc-chev">&#9662;</span>';
  hdr.addEventListener('click', ()=>el.classList.toggle('coll'));
  el.appendChild(hdr);

  const body = document.createElement('div');
  body.className = 'sc-body';

  const ch = document.createElement('div');
  ch.className = 'bch';
  ch.innerHTML = '<span class="bch-b">pg</span><span class="bch-h">hex</span><span class="bch-a">ascii</span><span class="bch-n">decoded</span>';
  body.appendChild(ch);

  for (let p = 0; p < pages; p++) {
    const bytes = data.slice(p*BLOCK_MFU, p*BLOCK_MFU+BLOCK_MFU);
    body.appendChild(buildMFUPageRow(p, bytes, pages));
  }

  el.appendChild(body);
  frag.appendChild(el);
  db.appendChild(frag);
}

function buildMFUPageRow(p, bytes, totalPages) {
  const row = document.createElement('div');
  // Pages 0-2: UID/BCC — red; Page 3: OTP; rest: data
  const isUID = p < 3;
  const isOTP = p === 3;
  const isCfg = p >= totalPages - 5; // last 5 pages typically config/auth on most UL variants
  row.className = 'br' + (isUID ? ' mfr' : isCfg ? ' st' : '');

  let hexHtml = '';
  for (let i = 0; i < bytes.length; i++) {
    if (i) hexHtml += ' ';
    const x = byteHex(bytes[i]).toUpperCase();
    if (isUID) {
      // Page 0: UID0 UID1 UID2 CT(cascade tag)
      // Page 1: UID3 UID4 UID5 UID6
      // Page 2: BCC0 BCC1 LOCK0 LOCK1
      if (p===0 && i<3)       hexHtml += '<span class="b-u">'+x+'</span>';
      else if (p===0 && i===3) hexHtml += '<span class="b-bcc">'+x+'</span>'; // CT
      else if (p===1)          hexHtml += '<span class="b-u">'+x+'</span>';
      else if (p===2 && i<2)  hexHtml += '<span class="b-bcc">'+x+'</span>'; // BCC0/BCC1
      else                     hexHtml += '<span class="b-sak">'+x+'</span>'; // LOCK
    } else if (isOTP) {
      hexHtml += '<span class="b-atqa">'+x+'</span>';
    } else if (bytes[i] === 0) {
      hexHtml += '<span class="b-0">'+x+'</span>';
    } else {
      hexHtml += '<span class="b-d">'+x+'</span>';
    }
  }

  const note = p===0 ? 'UID[0-2] + Cascade Tag'
             : p===1 ? 'UID[3-6]'
             : p===2 ? 'BCC0 + BCC1 + Static Lock Bytes'
             : p===3 ? 'OTP (One-Time Programmable)'
             : isCfg ? 'Config / Auth area'
             : '';

  row.innerHTML =
    '<span class="br-b">' + p + '</span>' +
    '<span class="br-h">' + hexHtml + '</span>' +
    '<span class="br-a">' + escHtml(asciiOf(bytes)) + '</span>' +
    '<span class="br-n">' + escHtml(note) + '</span>';
  return row;
}

// ── NAVIGATION ──
function jumpToSector(s) {
  curSec = s;
  document.querySelectorAll('.si').forEach((el,i)=>el.classList.toggle('on',i===s));
  document.querySelectorAll('.si')[s]?.scrollIntoView({block:'nearest',behavior:'smooth'});
  document.querySelectorAll('.ms-i').forEach((el,i)=>el.classList.toggle('on',i===s));
  document.getElementById('sec-'+s)?.scrollIntoView({block:'start',behavior:'smooth'});
  document.getElementById('st-r').textContent = 'Sector '+s;
}
function jumpToPage(p) {
  const el = document.getElementById('sec-0');
  if (!el) return;
  const rows = el.querySelectorAll('.br');
  if (rows[p]) rows[p].scrollIntoView({block:'start',behavior:'smooth'});
}
function jumpS(dir) {
  if (card && card.family==='ultralight') return;
  jumpToSector(Math.max(0, Math.min((card?card.sectors:1)-1, curSec+dir)));
}

// ── SAVE ──

function saveAs(fmt) {
  if (!dump) return;
  const base = fname.replace(/\.[^.]+$/, '');

  if (fmt === 'bin') {
    const blob = new Blob([dump], { type: 'application/octet-stream' });
    dlBlob(blob, base + '.bin');

  } else if (fmt === 'json') {
    const bsize = card.family === 'ultralight' ? 4 : 16;
    const data  = (card.family === 'ultralight' && card.hasPrefix)
                    ? dump.slice(card.prefixLen) : dump;
    const count = Math.floor(data.length / bsize);

    // blocks object — "0": "hex...", "1": "hex...", ...
    const blocks = {};
    for (let i = 0; i < count; i++) {
      blocks[String(i)] = Array.from(data.slice(i * bsize, i * bsize + bsize))
        .map(b => byteHex(b).toUpperCase()).join('');
    }

    // Card header — pull ATQA and SAK from block 0 bytes (Classic only)
    const uid  = Array.from(dump.slice(0,4)).map(b=>byteHex(b).toUpperCase()).join('');
    const atqa = byteHex(dump[6]).toUpperCase() + byteHex(dump[7]).toUpperCase(); // bytes 6,7 = ATQA[0],ATQA[1]
    const sak  = byteHex(dump[5]).toUpperCase();

    // SectorKeys — extracted from each sector trailer block
    const SectorKeys = {};
    if (card.family === 'classic') {
      for (let s = 0; s < card.sectors; s++) {
        const stb  = firstBlk(s) + blksPerSec(s) - 1;
        const sd   = Array.from(data.slice(stb * 16, stb * 16 + 16));
        const keyA = sd.slice(0,6).map(b=>byteHex(b).toUpperCase()).join('');
        const keyB = sd.slice(10,16).map(b=>byteHex(b).toUpperCase()).join('');
        const ac   = sd.slice(6,10).map(b=>byteHex(b).toUpperCase()).join('');

        // AccessConditionsText — decode each block using mifare4.c logic
        const acBytes = data.slice(stb * 16 + 6, stb * 16 + 9);
        const d1 = (acBytes[1] >> 4) & 0x0F;
        const d2 =  acBytes[2]       & 0x0F;
        const d3 = (acBytes[2] >> 4) & 0x0F;
        const nb = blksPerSec(s);
        const fb = firstBlk(s);
        const acText = {};
        for (let i = 0; i < nb; i++) {
          const cond = ((d1>>i)&1)<<2 | ((d2>>i)&1)<<1 | ((d3>>i)&1);
          const key  = i === nb-1 ? 'block' + stb : 'block' + (fb + i);
          acText[key] = i === nb-1
            ? (ST_AC[cond] ? ST_AC[cond].label : 'unknown')
            : (DATA_AC[cond] ? DATA_AC[cond].label : 'unknown');
        }
        acText['UserData'] = byteHex(sd[9]).toUpperCase();

        SectorKeys[String(s)] = {
          KeyA: keyA,
          KeyB: keyB,
          AccessConditions: ac,
          AccessConditionsText: acText,
        };
      }
    }

    const obj = {
      Created:  'MFView',
      FileType: 'mfc v2',
      Card: { UID: uid, ATQA: atqa, SAK: sak },
      blocks,
      SectorKeys,
    };

    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    dlBlob(blob, base + '.json');
  }
}

function dlBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function tog(key) {
  opts[key] = !opts[key];
  document.getElementById('btn-'+key).classList.toggle('on', opts[key]);
  if (dump) render();
}
function setVM(m) {
  vm = m;
  ['all','data'].forEach(x=>document.getElementById('vm-'+x).classList.toggle('on',x===m));
  if (dump) render();
}

// ── SIDEBAR / SHEET ──
function togSB() {
  if (window.innerWidth>700) {
    collapseDesktopSB();
  } else openMS();
}
function collapseDesktopSB() {
  document.getElementById('app').classList.toggle('sb-collapsed');
}
function openMS()  { const s=document.getElementById('ms'); s.style.display='block'; requestAnimationFrame(()=>s.classList.add('on')); }
function closeMS() { const s=document.getElementById('ms'); s.classList.remove('on'); setTimeout(()=>s.style.display='none',260); }

// ── SUPPORTED TYPES TOOLTIP ──
function toggleSupportedTypes(e) {
  e.stopPropagation();
  const tip = document.getElementById('st-tip');
  tip.classList.toggle('on');
  if (tip.classList.contains('on')) {
    setTimeout(() => document.addEventListener('click', dismissSupportedTypes, { once: true }), 0);
  }
}
function closeSupportedTypes() {
  document.getElementById('st-tip').classList.remove('on');
}
function dismissSupportedTypes() {
  document.getElementById('st-tip').classList.remove('on');
}

// ── SAVE ──

function byteHex(b)    { return b.toString(16).padStart(2,'0'); }
function hexStr(b,o,n) { let s=''; for(let i=0;i<n;i++){if(i)s+=' ';s+=byteHex(b[o+i]);} return s; }
function asciiOf(b)    { return Array.from(b).map(v=>(v>=0x20&&v<0x7f)?String.fromCharCode(v):'\u00b7').join(''); }
function escHtml(s)    { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function setSt(m)      { document.getElementById('st-txt').textContent = m; }

// ── KEYBOARD ──
document.addEventListener('keydown', e => {
  if (e.key==='Escape')                         closeMS();
  if ((e.ctrlKey||e.metaKey)&&e.key==='o')      { e.preventDefault(); triggerOpen(); }
  if (e.key==='PageDown')                        { e.preventDefault(); jumpS(1); }
  if (e.key==='PageUp')                          { e.preventDefault(); jumpS(-1); }
});
