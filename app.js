// ============================================================
//  PN532 HSU Protocol Layer
// ============================================================

const WAKEUP_BYTES = new Uint8Array([
  0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
]);

class PN532 {
  constructor() {
    this.port = null;
    this.reader = null;
    this.writer = null;
    this.readBuf = [];
    this.connected = false;
    this._reading = false;
  }

  buildFrame(data) {
    const len = data.length;
    let sum = 0;
    for (const b of data) sum += b;
    const f = new Uint8Array(7 + len);
    f[0] = 0x00;
    f[1] = 0x00;
    f[2] = 0xff;
    f[3] = len;
    f[4] = (0x100 - len) & 0xff;
    f.set(data, 5);
    f[5 + len] = (0x100 - (sum & 0xff)) & 0xff;
    f[6 + len] = 0x00;
    return f;
  }

  async writeFrame(data) {
    const frame = this.buildFrame(data);
    logTx(frame);
    await this.writer.write(frame);
  }

  async readFrame(timeout = 2000) {
    const start = performance.now();
    while (performance.now() - start < timeout) {
      const result = this._parseBuffer();
      if (result) return result;
      await sleep(10);
    }
    throw new Error('Read timeout');
  }

  _parseBuffer() {
    const buf = this.readBuf;
    while (true) {
      let start = -1;
      for (let i = 0; i < buf.length - 2; i++) {
        if (buf[i] === 0x00 && buf[i + 1] === 0x00 && buf[i + 2] === 0xff) {
          start = i;
          break;
        }
      }
      if (start < 0) {
        buf.length = 0;
        return null;
      }
      if (start > 0) buf.splice(0, start);
      if (buf.length < 5) return null;

      const len = buf[3];
      const lcs = buf[4];

      if (len === 0x00 && lcs === 0xff) {
        buf.splice(0, 6);
        continue;
      }
      if (len === 0xff && lcs === 0x00) {
        logInfo('NACK');
        buf.splice(0, 6);
        continue;
      }
      if (((len + lcs) & 0xff) !== 0) {
        buf.splice(0, 3);
        continue;
      }

      const totalFrame = 5 + len + 1;
      if (buf.length < totalFrame) return null;

      const data = buf.slice(5, 5 + len);
      const dcs = buf[5 + len];

      let dcsCalc = 0;
      for (const b of data) dcsCalc += b;
      dcsCalc = (0x100 - (dcsCalc & 0xff)) & 0xff;

      buf.splice(0, totalFrame);

      if (dcs !== dcsCalc) {
        logErr('DCS mismatch');
        continue;
      }

      logRx(data);
      return data;
    }
  }

  async sendCommand(data, timeout) {
    await this.writeFrame(data);
    return await this.readFrame(timeout);
  }
}

// ============================================================
//  MIFARE Classic Layer
// ============================================================

const MIFARE_DEFAULT_KEY = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
const BLOCKS_PER_SECTOR = 4;
const TOTAL_SECTORS_1K = 16;
const TOTAL_SECTORS_4K = 32;
const TOTAL_BLOCKS_1K = 64;
const TOTAL_BLOCKS_4K = 128;
const BLOCK_SIZE = 16;

function getSectorCount() {
  if (currentSAK === 0x18 || currentSAK === 0x19) return TOTAL_SECTORS_4K;
  if (currentSAK === 0x09) return 5;
  return TOTAL_SECTORS_1K;
}

function getBlockCount() {
  return getSectorCount() * BLOCKS_PER_SECTOR;
}

function trailerBlock(sector) {
  return sector * BLOCKS_PER_SECTOR + 3;
}

function isTrailerBlock(block) {
  return block % BLOCKS_PER_SECTOR === 3;
}

function isManufacturerBlock(block) {
  return block === 0;
}

function sectorOf(block) {
  return Math.floor(block / BLOCKS_PER_SECTOR);
}

function parseKey(hex) {
  if (hex.length !== 12) throw new Error('Key must be 12 hex chars');
  const k = [];
  for (let i = 0; i < 12; i += 2) k.push(parseInt(hex.substr(i, 2), 16));
  return k;
}

function hexStr(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join(' ');
}

function hexStrShort(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ============================================================
//  Known Keys Database (sorted by priority)
// ============================================================

const KNOWN_KEYS = [
  'FFFFFFFFFFFF',
  '000000000000',
  'A0A1A2A3A4A5',
  'D3F7D3F7D3F7',
  'A396EFA4E24F',
  'A31667A8CEC1',
  'A5A4A3A2A1A0',
  '89ECA97F8C2A',
  'B0B1B2B3B4B5',
  'C0C1C2C3C4C5',
  'D0D1D2D3D4D5',
  '4D3A99C351DD',
  '1A982C7E459A',
  'AABBCCDDEEFF',
  '010203040506',
  '123456789ABC',
  '0123456789AB',
  '000000000001',
  '000000000002',
  '00000000000A',
  '00000000000B',
  '111111111111',
  '222222222222',
  '333333333333',
  '444444444444',
  '555555555555',
  '666666666666',
  '777777777777',
  '888888888888',
  '999999999999',
  'AAAAAAAAAAAA',
  'BBBBBBBBBBBB',
  'CCCCCCCCCCCC',
  'DDDDDDDDDDDD',
  'EEEEEEEEEEEE',
  'FAFAFAFAFAFA',
  'FBFBFBFBFBFB',
  'ABCDEF123456',
  'BD493A3962B6',
  '434F4D4D4F41',
  '434F4D4D4F42',
  '47524F555041',
  '47524F555042',
  '505249564141',
  '505249564142',
  '54726176656C',
  '776974687573',
  '314B49474956',
  '564C505F4D41',
  '484558414354',
  '484944204953',
  '204752454154',
  '2A2C13CC242A',
  '8A19D40CF2B5',
  'AFBECD120454',
  'AFBECD121004',
  '842146108088',
  '96A301BCE267',
  '44AB09010845',
  'B62307B62307',
  '4D57414C5648',
  '4D48414C5648',
  'EC29806D9738',
  '08B386463229',
  '0E8F64340BA4',
  '2AA05ED1856F',
  '69A32F1C2F19',
  'A73F5DC1D333',
  'CD4C61C26E3D',
  '374BF468607F',
  'BFC8E353AF63',
  '62EFD80AB715',
  'FC00018778F7',
  '0297927C0F77',
  '668770666644',
  '003003003003',
  'A00000000000',
  'B00000000000',
  'E00000000000',
  '100000000000',
  '200000000000',
  '4B0B20107CCB',
  'A0478CC39091',
  '533CB6C723F6',
  '8FD0A4F256E9',
  'B7A6B4E8D2E5',
  '6B6579737472',
  '6B6579333273',
  '00000FFE2488',
  'FFFFFF545846',
  '190819842023',
  'AC37E76385F5',
];

const UNIQUE_KEYS = [...new Set(KNOWN_KEYS)];

// ============================================================
//  Card Type Detection (SAK + ATQA based)
// ============================================================

function detectCardType(sak, atqa) {
  const info = { type: 'Unknown', clonable: false, protocol: '?', notes: '' };
  const atqaVal = atqa ? (atqa[1] << 8) | atqa[0] : 0;

  switch (sak) {
    case 0x00:
      info.type = 'MIFARE Ultralight / NTAG';
      info.clonable = false;
      info.protocol = 'ISO 14443-3A';
      info.notes = 'Not MIFARE Classic \u2014 no crypto auth';
      if (atqaVal === 0x0044) {
        info.type = 'NTAG21x';
        info.notes = 'NTAG213/215/216 \u2014 password protected';
      }
      if (atqaVal === 0x0004) info.type = 'MIFARE Ultralight';
      if (atqaVal === 0x0042) info.type = 'MIFARE Ultralight C';
      break;
    case 0x08:
      info.type = 'MIFARE Classic 1K';
      info.clonable = true;
      info.protocol = 'ISO 14443-3A';
      info.notes = '16 sectors \u00d7 4 blocks \u2014 fully clonable with known keys';
      break;
    case 0x09:
      info.type = 'MIFARE Mini';
      info.clonable = true;
      info.protocol = 'ISO 14443-3A';
      info.notes = '5 sectors \u00d7 4 blocks (256 bytes) \u2014 clonable';
      break;
    case 0x18:
      info.type = 'MIFARE Classic 4K';
      info.clonable = true;
      info.protocol = 'ISO 14443-3A';
      info.notes = '32 sectors (4K) \u2014 clonable, larger memory';
      break;
    case 0x19:
      info.type = 'MIFARE Classic 4K';
      info.clonable = true;
      info.protocol = 'ISO 14443-3A';
      info.notes = '4K variant';
      break;
    case 0x04:
      info.type = 'MIFARE Ultralight';
      info.clonable = false;
      info.protocol = 'ISO 14443-3A';
      break;
    case 0x20:
      info.type = 'MIFARE DESFire';
      info.clonable = false;
      info.protocol = 'ISO 14443-4';
      info.notes = 'AES/3DES crypto \u2014 not directly clonable';
      break;
    case 0x28:
      info.type = 'MIFARE DESFire EV1';
      info.clonable = false;
      info.protocol = 'ISO 14443-4';
      info.notes = 'Crypto-authenticated \u2014 not clonable';
      break;
    case 0x50:
      info.type = 'MIFARE DESFire EV2/EV3';
      info.clonable = false;
      info.protocol = 'ISO 14443-4';
      info.notes = 'Advanced crypto \u2014 not clonable';
      break;
    case 0x10:
      info.type = 'MIFARE PLUS';
      info.clonable = false;
      info.protocol = 'ISO 14443-4';
      info.notes = 'AES-128 crypto';
      break;
    case 0x11:
      info.type = 'MIFARE PLUS SE';
      info.clonable = false;
      info.protocol = 'ISO 14443-4';
      break;
    default:
      if (sak & 0x04) {
        info.type = 'Not complete UID (cascade)';
        info.notes = 'SAK 0x' + sak.toString(16) + ' \u2014 may need multi-level anti-collision';
      } else {
        info.type = 'Unknown (SAK=0x' + sak.toString(16) + ')';
        info.notes = 'ATQA=0x' + atqaVal.toString(16).padStart(4, '0');
      }
  }

  if (atqaVal === 0x0044 && sak === 0x00) {
    info.type = 'NTAG21x (NTAG213/215/216)';
    info.notes = 'Password-protected, not MIFARE Classic';
  }
  if (atqaVal === 0x0002 && sak === 0x08) {
    info.type = 'MIFARE Classic 1K (NXP)';
    info.notes = 'Original NXP chip';
  }
  if (atqaVal === 0x0002 && (sak === 0x08 || sak === 0x18)) {
    info.notes += ' | NXP silicon';
  }
  if (atqaVal === 0x0004 && sak === 0x08) {
    info.notes += ' | Likely Fudan FM11RF08 clone';
  }

  return info;
}

function formatATQA(atqa) {
  if (!atqa || atqa.length < 2) return '---';
  const val = (atqa[1] << 8) | atqa[0];
  return '0x' + val.toString(16).padStart(4, '0').toUpperCase();
}

// ============================================================
//  Application State
// ============================================================

let pn532 = new PN532();
let currentUID = null;
let currentATQA = null;
let currentSAK = null;
let cardPresent = false;
let cloneBuffer = null;
let cloneBufferATQA = null;
let cloneBufferSAK = null;
let authedSector = -1;
let sectorKeys = Array.from({ length: TOTAL_SECTORS_4K }, () => ({
  a: 'FFFFFFFFFFFF',
  b: 'FFFFFFFFFFFF',
}));
let dumpData = Array.from({ length: TOTAL_BLOCKS_4K }, () => new Uint8Array(BLOCK_SIZE));
let scanning = false;
let scanInterval = null;

// State machine: disconnected | idle | scanning | card | busy
let state = 'disconnected';
let abortRequested = false;

const UI = {
  disconnected: {
    btnConnect: 0,
    btnDisconnect: 1,
    btnStop: 1,
    btnScan: 1,
    btnFindKeys: 1,
    btnDump: 1,
    btnCloneRead: 1,
    btnCloneWrite: 1,
    btnCloneClear: 0,
    btnRelease: 1,
    btnAuth: 1,
    btnReadBlock: 1,
    btnWriteBlock: 1,
    btnWriteUid: 1,
    actionsCard: 1,
    blockEditorCard: 1,
    cloneCard: 1,
    valueBlockCard: 1,
    dumpCard: 1,
  },
  idle: {
    btnConnect: 1,
    btnDisconnect: 0,
    btnStop: 1,
    btnScan: 0,
    btnFindKeys: 1,
    btnDump: 1,
    btnCloneRead: 1,
    btnCloneWrite: 1,
    btnCloneClear: 0,
    btnRelease: 1,
    btnAuth: 1,
    btnReadBlock: 1,
    btnWriteBlock: 1,
    btnWriteUid: 1,
    actionsCard: 0,
    blockEditorCard: 1,
    cloneCard: 1,
    valueBlockCard: 1,
    dumpCard: 1,
  },
  scanning: {
    btnConnect: 1,
    btnDisconnect: 0,
    btnStop: 0,
    btnScan: 1,
    btnFindKeys: 1,
    btnDump: 1,
    btnCloneRead: 1,
    btnCloneWrite: 1,
    btnCloneClear: 0,
    btnRelease: 1,
    btnAuth: 1,
    btnReadBlock: 1,
    btnWriteBlock: 1,
    btnWriteUid: 1,
    actionsCard: 0,
    blockEditorCard: 1,
    cloneCard: 1,
    valueBlockCard: 1,
    dumpCard: 1,
  },
  card: {
    btnConnect: 1,
    btnDisconnect: 0,
    btnStop: 1,
    btnScan: 0,
    btnFindKeys: 0,
    btnDump: 0,
    btnCloneRead: 0,
    btnCloneWrite: 0,
    btnCloneClear: 0,
    btnRelease: 0,
    btnAuth: 0,
    btnReadBlock: 0,
    btnWriteBlock: 0,
    btnWriteUid: 0,
    actionsCard: 0,
    blockEditorCard: 0,
    cloneCard: 0,
    valueBlockCard: 0,
    dumpCard: 0,
  },
  busy: {
    btnConnect: 1,
    btnDisconnect: 1,
    btnStop: 0,
    btnScan: 1,
    btnFindKeys: 1,
    btnDump: 1,
    btnCloneRead: 1,
    btnCloneWrite: 1,
    btnCloneClear: 1,
    btnRelease: 1,
    btnAuth: 1,
    btnReadBlock: 1,
    btnWriteBlock: 1,
    btnWriteUid: 1,
    actionsCard: 0,
    blockEditorCard: 1,
    cloneCard: 0,
    valueBlockCard: 1,
    dumpCard: 0,
  },
};

function setState(newState, opts) {
  state = newState;
  abortRequested = false;
  const defs = UI[newState];
  if (!defs) return;
  Object.entries(defs).forEach(([id, disabled]) => {
    const el = $(id);
    if (!el) return;
    if (id.endsWith('Card')) {
      el.classList.toggle('card-disabled', disabled);
    } else {
      el.disabled = !!disabled;
    }
  });
  $('btnStop').classList.toggle('hidden', newState !== 'busy');
  if (opts?.btnText) {
    const [id, text] = opts.btnText;
    $(id).innerHTML = text;
  }
  if (opts?.cardDisabled) {
    $('valueBlockCard').classList.toggle('card-disabled', !canDoValueOp(...opts.cardDisabled));
  }
}

function checkAbort() {
  if (abortRequested) throw new Error('Cancelled');
}

async function authSector(s, block) {
  if (authedSector === s) return true;
  const keyType = $('selKeyType').value;
  const keyHex = keyType === 'B' ? sectorKeys[s].b : sectorKeys[s].a;
  try {
    await mfAuth(1, block, parseKey(keyHex), currentUID);
    authedSector = s;
    return true;
  } catch (_) {}
  for (const k of UNIQUE_KEYS) {
    try {
      await mfAuth(1, block, parseKey(k), currentUID);
      if (keyType === 'A') sectorKeys[s].a = k;
      else sectorKeys[s].b = k;
      authedSector = s;
      updateKeyStorage();
      logInfo(`Sector ${s}: found key ${keyType} = ${k}`);
      return true;
    } catch (_) {}
  }
  return false;
}

// ============================================================
//  UI Helpers
// ============================================================

function $(id) {
  return document.getElementById(id);
}

function toast(msg, ok = true) {
  const el = document.createElement('div');
  el.className = 'toast ' + (ok ? 'toast-ok' : 'toast-err');
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2500);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function logTx(data) {
  appendLog('TX: ' + hexStr(data), 'log-tx');
}

function logRx(data) {
  appendLog('RX: ' + hexStr(data), 'log-rx');
}

function logInfo(msg) {
  appendLog(msg, 'log-info');
}

function logErr(msg) {
  appendLog('ERR: ' + msg, 'log-err');
}

function appendLog(msg, cls) {
  const box = $('logBox');
  const line = document.createElement('div');
  line.className = cls;
  line.textContent = msg;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
  while (box.children.length > 200) box.removeChild(box.firstChild);
}

function clearLog() {
  $('logBox').innerHTML = '';
}

function setConnected(c) {
  pn532.connected = c;
  $('statusDot').className = 'dot' + (c ? ' connected' : '');
  if (!c) {
    cardPresent = false;
    currentUID = null;
    currentATQA = null;
    currentSAK = null;
    setState('disconnected');
    updateCardInfo();
  } else {
    setState('idle');
  }
}

function updateCardInfo() {
  $('cardStatus').textContent = cardPresent ? 'Card present' : 'No card';
  $('cardUID').textContent = currentUID ? hexStrShort(currentUID) : '---';
  $('cardATQA').textContent = formatATQA(currentATQA);
  $('cardSAK').textContent =
    currentSAK !== null ? '0x' + currentSAK.toString(16).padStart(2, '0') : '---';

  const cloneEl = $('clonability');
  if (currentSAK !== null) {
    const info = detectCardType(currentSAK, currentATQA);
    $('cardType').textContent = info.type;

    if (info.clonable) {
      cloneEl.className = '';
      cloneEl.style.background = '#35aa1222';
      cloneEl.style.border = '1px solid #35aa12';
      cloneEl.style.color = '#35aa12';
      cloneEl.textContent = 'Clonable \u2014 ' + info.notes;
    } else {
      cloneEl.className = '';
      cloneEl.style.background = '#e1705522';
      cloneEl.style.border = '1px solid #e17055';
      cloneEl.style.color = '#e17055';
      cloneEl.textContent = 'Not clonable \u2014 ' + info.notes;
    }
  } else {
    $('cardType').textContent = '---';
    cloneEl.className = 'hidden';
  }

  if (state !== 'busy') {
    setState(cardPresent ? 'card' : 'idle');
  }
}

function updateKeyStorage() {
  const tbody = $('keyBody');
  tbody.innerHTML = '';
  for (let s = 0; s < getSectorCount(); s++) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${s}</td><td style="color:var(--accent)">${sectorKeys[s].a}</td><td style="color:var(--yellow)">${sectorKeys[s].b}</td>`;
    tr.style.cursor = 'pointer';
    tr.onclick = () => {
      $('selSector').value = s;
      onSectorChange();
      $('keyA').value = sectorKeys[s].a;
      $('keyB').value = sectorKeys[s].b;
    };
    tbody.appendChild(tr);
  }
}

function onSectorChange() {
  const s = parseInt($('selSector').value);
  $('keyA').value = sectorKeys[s].a;
  $('keyB').value = sectorKeys[s].b;
  const blockSel = $('selBlock');
  blockSel.innerHTML = '';
  for (let b = 0; b < BLOCKS_PER_SECTOR; b++) {
    const opt = document.createElement('option');
    opt.value = b;
    opt.textContent = b + (isTrailerBlock(s * BLOCKS_PER_SECTOR + b) ? ' (trailer)' : '');
    blockSel.appendChild(opt);
  }
  blockSel.value = 0;
  onBlockChange();
}

function onBlockChange() {
  const s = parseInt($('selSector').value);
  const b = parseInt($('selBlock').value);
  const block = s * BLOCKS_PER_SECTOR + b;
  const data = dumpData[block];
  $('hexEditor').textContent = hexStr(data);
  updateAsciiPreview();
  updateValueDisplay(data);
  updateBlockInfo(s, b, block);
  updateValueBlockCard(s, block);
}

function canDoValueOp(s, block) {
  if (s === 0 && block === 0) return false;
  if (isTrailerBlock(block)) return false;
  return true;
}

function updateValueBlockCard(s, block) {
  const card = $('valueBlockCard');
  if (canDoValueOp(s, block)) {
    card.classList.remove('card-disabled');
  } else {
    card.classList.add('card-disabled');
  }
}

function updateBlockInfo(s, b, block) {
  let desc = '';
  if (s === 0 && b === 0) {
    desc = 'Manufacturer block (read-only, except on magic cards)';
  } else if (isTrailerBlock(block)) {
    desc = 'Trailer (Key A + Access + Key B)';
  } else {
    desc = 'Data block';
  }
  $('blockInfo').textContent = `Block ${block} (S${s} B${b}) \u2014 ${desc}`;

  const uidRow = $('uidEditRow');
  if (block === 0) {
    uidRow.classList.remove('hidden');
    const data = dumpData[0];
    if (data) {
      const uid = data
        .slice(0, 4)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('')
        .toUpperCase();
      $('uidEdit').value = uid;
    } else {
      $('uidEdit').value = '';
    }
  } else {
    uidRow.classList.add('hidden');
  }
}

async function doWriteUid() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  const uidHex = $('uidEdit').value.replace(/\s/g, '').toUpperCase();
  if (uidHex.length !== 8 || !/^[0-9A-F]{8}$/.test(uidHex)) {
    toast('UID must be 8 hex characters (4 bytes)', false);
    return;
  }

  const uidBytes = [];
  for (let i = 0; i < 8; i += 2) {
    uidBytes.push(parseInt(uidHex.substr(i, 2), 16));
  }

  try {
    const keyType = $('selKeyType').value;
    const keyHex = keyType === 'B' ? sectorKeys[0].b : sectorKeys[0].a;
    await mfAuth(1, 0, parseKey(keyHex), currentUID);

    const existing = dumpData[0] || new Uint8Array(16);
    const newBlock = new Uint8Array(16);
    newBlock.set(uidBytes, 0);
    newBlock.set(existing.slice(4), 4);

    await mfWriteBlock(1, 0, newBlock);
    dumpData[0] = newBlock;
    updateDumpTable();
    toast(`UID written: ${uidHex}`);
  } catch (e) {
    if (e.message === 'Timeout') {
      toast('Block 0 write failed — card is not a magic/clonable card', false);
      logErr('Write UID: standard MIFARE Classic block 0 is read-only');
    } else {
      logErr('Write UID error: ' + e.message);
      toast('Write UID failed: ' + e.message, false);
    }
  }
}

function updateAsciiPreview() {
  const hex = $('hexEditor').textContent.replace(/\s+/g, '');
  let ascii = '';
  for (let i = 0; i < hex.length; i += 2) {
    const code = parseInt(hex.substr(i, 2), 16);
    ascii += code >= 0x20 && code < 0x7f ? String.fromCharCode(code) : '.';
  }
  $('asciiPreview').textContent = ascii;
}

function updateValueDisplay(data) {
  if (!data || data.length < 4) {
    $('valueDisplay').textContent = '---';
    return;
  }
  const allZero = data.every((b) => b === 0);
  if (allZero) {
    $('valueDisplay').textContent = '---';
    return;
  }
  const v = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
  const inv = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
  const v2 = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
  if ((v ^ 0xffffffff) === inv && v === v2) {
    $('valueDisplay').textContent = v.toString();
  } else {
    $('valueDisplay').textContent = '(not a value block)';
  }
}

function setDefaultKeys() {
  sectorKeys = Array.from({ length: TOTAL_SECTORS_4K }, () => ({
    a: 'FFFFFFFFFFFF',
    b: 'FFFFFFFFFFFF',
  }));
  updateKeyStorage();
  toast('Keys reset to default');
}

function applyKeyToAll() {
  const key = $('keyA').value.toUpperCase();
  if (key.length !== 12) {
    toast('Invalid key', false);
    return;
  }
  for (let s = 0; s < getSectorCount(); s++) sectorKeys[s].a = key;
  updateKeyStorage();
  toast('Key A applied to all sectors');
}

function updateDumpTable() {
  const tbody = $('dumpBody');
  tbody.innerHTML = '';
  for (let s = 0; s < getSectorCount(); s++) {
    for (let b = 0; b < BLOCKS_PER_SECTOR; b++) {
      const block = s * BLOCKS_PER_SECTOR + b;
      const tr = document.createElement('tr');
      const isTrailer = isTrailerBlock(block);
      const isMfg = isManufacturerBlock(block);
      tr.className = '';
      const blockCellClass = isTrailer
        ? 'block-num trailer'
        : isMfg
          ? 'block-num read-only'
          : 'block-num';
      tr.innerHTML = `<td class="${blockCellClass}">${s}</td><td class="${blockCellClass}">${b}${isTrailer ? 'T' : isMfg ? 'R' : ''}</td><td style="font-family:var(--mono);font-size:0.72rem;">${hexStr(dumpData[block])}</td>`;
      tr.style.cursor = 'pointer';
      tr.onclick = () => {
        $('selSector').value = s;
        onSectorChange();
        $('selBlock').value = b;
        onBlockChange();
      };
      tbody.appendChild(tr);
    }
  }
}

// ============================================================
//  Hex Editor Helpers
// ============================================================

$('hexEditor').addEventListener('input', () => {
  let text = $('hexEditor')
    .textContent.replace(/[^0-9a-fA-F\s]/g, '')
    .toUpperCase();
  const bytes = text.replace(/\s+/g, '').match(/.{1,2}/g) || [];
  $('hexEditor').textContent = bytes.join(' ');
  updateAsciiPreview();
});

function getHexEditorBytes() {
  const hex = $('hexEditor').textContent.replace(/\s+/g, '');
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}

// ============================================================
//  PN532 Communication Functions
// ============================================================

async function doConnect() {
  try {
    if (!('serial' in navigator)) {
      toast('Web Serial API not supported. Use Chrome/Edge 89+.', false);
      return;
    }
    pn532.port = await navigator.serial.requestPort();
    logInfo('Port selected');

    for (const baud of [115200, 9600]) {
      try {
        try {
          await pn532.port.close();
        } catch (_) {}
        await pn532.port.open({
          baudRate: baud,
          dataBits: 8,
          stopBits: 1,
          parity: 'none',
        });
        logInfo(`Opened at ${baud} baud`);

        pn532.writer = pn532.port.writable.getWriter();
        pn532.reader = pn532.port.readable.getReader();
        pn532._reading = true;

        (async () => {
          try {
            while (pn532._reading) {
              const { value, done } = await pn532.reader.read();
              if (done) break;
              for (let i = 0; i < value.length; i++) pn532.readBuf.push(value[i]);
            }
          } catch (e) {
            if (pn532._reading) logErr('Read loop: ' + e.message);
          }
        })();

        logInfo('Waking up PN532...');
        const samCmd = pn532.buildFrame([0xd4, 0x14, 0x01, 0x14, 0x01]);
        const wakeAndSam = new Uint8Array(16 + samCmd.length);
        wakeAndSam.set([0x55, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0);
        wakeAndSam.set(samCmd, 16);
        logTx(wakeAndSam);
        await pn532.writer.write(wakeAndSam);

        const sam = await pn532.readFrame(2000);
        if (sam && sam.length >= 2 && sam[1] === 0x15) {
          logInfo('SAM configured: Normal mode');
        } else {
          throw new Error('SAMConfiguration failed: ' + hexStr(sam || []));
        }

        const rf = await pn532.sendCommand([0xd4, 0x32, 0x05, 0xff, 0x01, 0x01], 1000);
        if (rf && rf.length >= 2 && rf[1] === 0x33) {
          logInfo('RF configured');
        } else {
          logInfo('RF response: ' + hexStr(rf || []));
        }

        const fw = await pn532.sendCommand([0xd4, 0x02], 1000);
        if (fw && fw.length >= 2 && fw[1] === 0x03) {
          logInfo('PN532 FW: v' + fw[2] + '.' + fw[3]);
        }

        setConnected(true);
        toast(`Connected at ${baud} baud`);
        return;
      } catch (e) {
        logErr(`Baud ${baud} failed: ${e.message}`);
        await cleanupPort();
      }
    }
    toast('Failed to connect at any baud rate', false);
  } catch (e) {
    if (e.name !== 'NotFoundError') {
      logErr('Connect error: ' + e.message);
      toast('Connection failed: ' + e.message, false);
    }
  }
}

async function cleanupPort() {
  pn532._reading = false;
  try {
    if (pn532.reader) pn532.reader.releaseLock();
  } catch (_) {}
  try {
    if (pn532.writer) pn532.writer.releaseLock();
  } catch (_) {}
  pn532.reader = null;
  pn532.writer = null;
  pn532.readBuf = [];
  try {
    if (pn532.port) await pn532.port.close();
  } catch (_) {}
}

function doStop() {
  if (state === 'busy') {
    abortRequested = true;
    logInfo('Stop requested...');
  }
  if (state === 'scanning') {
    scanning = false;
    if (scanInterval) {
      clearInterval(scanInterval);
      scanInterval = null;
    }
    $('btnScan').textContent = 'Scan Card';
    setState('idle');
    toast('Scan stopped');
  }
}

async function doDisconnect() {
  scanning = false;
  if (scanInterval) {
    clearInterval(scanInterval);
    scanInterval = null;
  }
  await cleanupPort();
  pn532.port = null;
  setConnected(false);
  toast('Disconnected');
}

async function detectCard() {
  const res = await pn532.sendCommand([0xd4, 0x4a, 0x01, 0x00], 1500);
  if (!res || res.length < 2 || res[1] !== 0x4b) return null;
  const nbTg = res[2];
  if (nbTg === 0) return null;

  const sak = res[6];
  const uidLen = res[7];
  if (!uidLen || res.length < 8 + uidLen) return null;
  const uid = res.slice(8, 8 + uidLen);
  const atqa = res.slice(4, 6);

  return { uid, atqa, sak };
}

async function inDataExchange(tg, data, timeout) {
  const payload = [0xd4, 0x40, tg, ...data];
  const res = await pn532.sendCommand(payload, timeout || 2000);
  if (!res || res.length < 3 || res[1] !== 0x41) throw new Error('Invalid InDataExchange response');
  const status = res[2];
  if (status !== 0) {
    const errors = {
      0x01: 'Timeout',
      0x02: 'CRC error',
      0x03: 'Parity error',
      0x07: 'Buffer too small',
      0x0a: 'No card in field',
      0x14: 'Auth failed (wrong key?)',
      0x27: 'Command not valid',
      0x29: 'Card released',
    };
    throw new Error(errors[status] || 'Error 0x' + status.toString(16));
  }
  return res.slice(2);
}

async function mfAuth(tg, block, keyBytes, uid) {
  const sector = sectorOf(block);
  const trailer = trailerBlock(sector);
  const keyType = $('selKeyType').value === 'B' ? 0x61 : 0x60;
  const authData = [keyType, trailer, ...keyBytes, ...uid.slice(0, 4)];
  await inDataExchange(tg, authData, 2000);
  authedSector = sector;
}

async function mfReadBlock(tg, block) {
  const data = await inDataExchange(tg, [0x30, block], 2000);
  if (data.length < 17) throw new Error('Read response too short');
  return data.slice(1, 17);
}

async function mfWriteBlock(tg, block, data) {
  if (data.length !== 16) throw new Error('Write data must be 16 bytes');
  await inDataExchange(tg, [0xa0, block, ...data], 2000);
}

async function mfHalt(tg) {
  try {
    await inDataExchange(tg, [0x50, 0x00], 500);
  } catch (e) {}
}

// ============================================================
//  UI Actions
// ============================================================

async function doScan() {
  if (!pn532.connected) {
    toast('Not connected', false);
    return;
  }
  if (scanning) {
    scanning = false;
    if (scanInterval) {
      clearInterval(scanInterval);
      scanInterval = null;
    }
    $('btnScan').textContent = 'Scan Card';
    setState('idle');
    return;
  }

  setState('scanning');
  $('btnScan').innerHTML = '<span class="spinner"></span> Scanning...';
  scanning = true;

  const startTime = Date.now();
  const timeout = 15000;

  const poll = async () => {
    if (!scanning) return;
    if (Date.now() - startTime > timeout) {
      scanning = false;
      if (scanInterval) {
        clearInterval(scanInterval);
        scanInterval = null;
      }
      $('btnScan').textContent = 'Scan Card';
      setState('idle');
      toast('Scan timed out — no card found', false);
      return;
    }
    try {
      const card = await detectCard();
      if (card) {
        currentUID = card.uid;
        currentATQA = card.atqa;
        currentSAK = card.sak;
        cardPresent = true;
        scanning = false;
        if (scanInterval) {
          clearInterval(scanInterval);
          scanInterval = null;
        }
        $('btnScan').textContent = 'Scan Card';
        updateCardInfo();
        toast('Card detected: ' + hexStrShort(card.uid));
      }
    } catch (e) {
      logErr('Scan error: ' + e.message);
    }
  };

  await poll();
  if (scanning) scanInterval = setInterval(poll, 500);
}

async function doFindKeys() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  if (state === 'busy') return;
  setState('busy');

  const maxSector = currentSAK === 0x18 || currentSAK === 0x19 ? 32 : currentSAK === 0x09 ? 5 : 16;

  logInfo(`Finding keys for ${maxSector} sectors (${UNIQUE_KEYS.length} keys to try)...`);
  $('btnFindKeys').innerHTML = '<span class="spinner"></span> Finding...';

  let found = 0;
  const startTime = performance.now();

  try {
    for (let s = 0; s < maxSector; s++) {
      checkAbort();
      if (sectorKeys[s].a !== 'FFFFFFFFFFFF' || sectorKeys[s].b !== 'FFFFFFFFFFFF') {
        logInfo(`Sector ${s}: already have keys (A=${sectorKeys[s].a} B=${sectorKeys[s].b})`);
        found++;
        continue;
      }

      const trailer = trailerBlock(s);
      let foundA = false,
        foundB = false;

      for (const keyHex of UNIQUE_KEYS) {
        checkAbort();
        if (foundA && foundB) break;

        const keyBytes = parseKey(keyHex);

        if (!foundA) {
          try {
            await mfAuth(1, s * BLOCKS_PER_SECTOR, keyBytes, currentUID);
            sectorKeys[s].a = keyHex;
            foundA = true;
            logInfo(`Sector ${s}: Key A = ${keyHex}`);
            await sleep(10);
          } catch (e) {
            await sleep(5);
          }
        }

        if (!foundB) {
          try {
            const keyBBytes = parseKey(keyHex);
            await inDataExchange(1, [0x61, trailer, ...keyBBytes, ...currentUID.slice(0, 4)], 2000);
            sectorKeys[s].b = keyHex;
            foundB = true;
            logInfo(`Sector ${s}: Key B = ${keyHex}`);
            await sleep(10);
          } catch (e) {
            await sleep(5);
          }
        }
      }

      if (foundA || foundB) found++;
      if (!foundA && !foundB) {
        logInfo(`Sector ${s}: no known keys found`);
      }

      updateKeyStorage();
    }
    const elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
    toast(`Found keys in ${found}/${maxSector} sectors (${elapsed}s)`);
  } catch (e) {
    if (e.message === 'Cancelled') {
      logInfo('Find keys cancelled');
      toast('Find keys cancelled');
    } else {
      logErr('Find keys error: ' + e.message);
    }
  } finally {
    $('btnFindKeys').textContent = 'Find Keys';
    updateKeyStorage();
    setState('card');
  }
}

async function doRelease() {
  if (!pn532.connected || !cardPresent) return;
  try {
    await mfHalt(1);
    cardPresent = false;
    currentUID = null;
    currentATQA = null;
    currentSAK = null;
    authedSector = -1;
    updateCardInfo();
    toast('Card released');
  } catch (e) {
    logErr('Release error: ' + e.message);
  }
}

async function doAuth() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  const s = parseInt($('selSector').value);
  const block = s * BLOCKS_PER_SECTOR;
  if (await authSector(s, block)) {
    toast(`Authenticated sector ${s}`);
  } else {
    toast('Auth failed — no working key found', false);
  }
}

async function doReadBlock() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  const s = parseInt($('selSector').value);
  const b = parseInt($('selBlock').value);
  const block = s * BLOCKS_PER_SECTOR + b;

  if (!(await authSector(s, block))) {
    toast('Auth failed', false);
    return;
  }

  try {
    const data = await mfReadBlock(1, block);
    dumpData[block] = data;
    $('hexEditor').textContent = hexStr(data);
    updateAsciiPreview();
    updateValueDisplay(data);
    toast(`Block ${block} read`);
  } catch (e) {
    logErr('Read error: ' + e.message);
    toast('Read failed: ' + e.message, false);
  }
}

async function doWriteBlock() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  const s = parseInt($('selSector').value);
  const b = parseInt($('selBlock').value);
  const block = s * BLOCKS_PER_SECTOR + b;

  if (isManufacturerBlock(block)) {
    toast('Cannot write to manufacturer block', false);
    return;
  }

  const data = getHexEditorBytes();
  if (data.length < 16) {
    toast('Need 16 bytes of data', false);
    return;
  }

  if (!(await authSector(s, block))) {
    toast('Auth failed', false);
    return;
  }

  try {
    await mfWriteBlock(1, block, data.slice(0, 16));
    dumpData[block] = data.slice(0, 16);
    toast(`Block ${block} written`);
  } catch (e) {
    logErr('Write error: ' + e.message);
    toast('Write failed: ' + e.message, false);
  }
}

async function doDump() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  if (state === 'busy') return;
  setState('busy');
  logInfo('Starting full dump...');
  $('btnDump').innerHTML = '<span class="spinner"></span> Dumping...';

  let errors = 0;
  try {
    for (let s = 0; s < getSectorCount(); s++) {
      for (let b = 0; b < BLOCKS_PER_SECTOR; b++) {
        checkAbort();
        const block = s * BLOCKS_PER_SECTOR + b;
        let ok = false;
        for (let attempt = 0; attempt < 3 && !ok; attempt++) {
          checkAbort();
          try {
            if (b === 0) {
              const keyType = $('selKeyType').value;
              const keyHex = keyType === 'B' ? sectorKeys[s].b : sectorKeys[s].a;
              await mfAuth(1, block, parseKey(keyHex), currentUID);
              authedSector = s;
              await sleep(10);
            }
            const data = await mfReadBlock(1, block);
            dumpData[block] = data;
            ok = true;
          } catch (e) {
            if (attempt < 2) {
              logInfo(`Sector ${s} Block ${b}: ${e.message}, retry ${attempt + 2}/3`);
              authedSector = -1;
              await sleep(50 * (attempt + 1));
            } else {
              logErr(`Sector ${s} Block ${b}: ${e.message} after 3 attempts`);
              errors++;
              authedSector = -1;
            }
          }
        }
        updateDumpTable();
        await sleep(15);
      }
    }
    toast(`Dump complete (${errors} errors)`, errors === 0);
  } catch (e) {
    if (e.message === 'Cancelled') {
      logInfo('Dump cancelled');
      toast('Dump cancelled');
    } else {
      logErr('Dump error: ' + e.message);
    }
  } finally {
    $('btnDump').textContent = 'Dump All';
    updateDumpTable();
    setState('card');
  }
}

async function doCloneRead() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  if (state === 'busy') return;
  setState('busy');
  logInfo('Clone: reading card...');
  $('btnCloneRead').innerHTML = '<span class="spinner"></span> Reading...';

  try {
    cloneBuffer = [];
    for (let s = 0; s < getSectorCount(); s++) {
      for (let b = 0; b < BLOCKS_PER_SECTOR; b++) {
        checkAbort();
        const block = s * BLOCKS_PER_SECTOR + b;
        let data = null;
        for (let attempt = 0; attempt < 3 && !data; attempt++) {
          checkAbort();
          try {
            if (b === 0) {
              const keyType = $('selKeyType').value;
              const keyHex = keyType === 'B' ? sectorKeys[s].b : sectorKeys[s].a;
              await mfAuth(1, block, parseKey(keyHex), currentUID);
              authedSector = s;
              await sleep(10);
            }
            data = await mfReadBlock(1, block);
          } catch (e) {
            if (attempt < 2) {
              logInfo(`Clone S${s}B${b}: ${e.message}, retry ${attempt + 2}/3`);
              authedSector = -1;
              await sleep(50 * (attempt + 1));
            } else {
              throw e;
            }
          }
        }
        cloneBuffer.push(data);
        await sleep(15);
      }
    }
    cloneBufferATQA = currentATQA;
    cloneBufferSAK = currentSAK;
    $('cloneStatus').textContent = `${cloneBuffer.length} blocks (${hexStrShort(currentUID)})`;
    toast('Card data read to buffer');
  } catch (e) {
    if (e.message === 'Cancelled') {
      logInfo('Clone read cancelled');
      toast('Clone read cancelled');
    } else {
      logErr('Clone read error: ' + e.message);
      toast('Clone read failed: ' + e.message, false);
    }
  } finally {
    $('btnCloneRead').textContent = 'Read to Buffer';
    setState('card');
  }
}

async function doCloneWrite() {
  if (!cloneBuffer || cloneBuffer.length === 0) {
    toast('Clone buffer is empty', false);
    return;
  }
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  if (state === 'busy') return;

  if (!confirm(`This will write ${cloneBuffer.length} blocks to the card. Continue?`)) return;

  setState('busy');
  logInfo('Clone: writing to card...');
  $('btnCloneWrite').innerHTML = '<span class="spinner"></span> Writing...';

  let errors = 0;
  try {
    for (let s = 0; s < getSectorCount(); s++) {
      for (let b = 0; b < BLOCKS_PER_SECTOR; b++) {
        checkAbort();
        const block = s * BLOCKS_PER_SECTOR + b;
        if (isManufacturerBlock(block)) continue;
        let ok = false;
        for (let attempt = 0; attempt < 3 && !ok; attempt++) {
          checkAbort();
          try {
            if (b === 0) {
              const keyType = $('selKeyType').value;
              const keyHex = keyType === 'B' ? sectorKeys[s].b : sectorKeys[s].a;
              await mfAuth(1, block, parseKey(keyHex), currentUID);
              authedSector = s;
              await sleep(10);
            }
            await mfWriteBlock(1, block, cloneBuffer[block]);
            ok = true;
          } catch (e) {
            if (attempt < 2) {
              logInfo(`Clone write S${s}B${b}: ${e.message}, retry ${attempt + 2}/3`);
              authedSector = -1;
              await sleep(50 * (attempt + 1));
            } else {
              logErr(`Clone write S${s}B${b}: ${e.message} after 3 attempts`);
              errors++;
              authedSector = -1;
            }
          }
        }
        await sleep(15);
      }
    }
    toast(`Clone write complete (${errors} errors)`, errors === 0);
  } catch (e) {
    if (e.message === 'Cancelled') {
      logInfo('Clone write cancelled');
      toast('Clone write cancelled');
    } else {
      logErr('Clone write error: ' + e.message);
    }
  } finally {
    $('btnCloneWrite').textContent = 'Write from Buffer';
    setState('card');
  }
}

function doCloneClear() {
  cloneBuffer = null;
  cloneBufferATQA = null;
  cloneBufferSAK = null;
  $('cloneStatus').textContent = 'Empty';
  toast('Clone buffer cleared');
}

function doSaveDump() {
  const sectorCount = getSectorCount();
  const totalBytes = sectorCount * BLOCKS_PER_SECTOR * BLOCK_SIZE;
  const buf = new Uint8Array(totalBytes);
  for (let s = 0; s < sectorCount; s++) {
    for (let b = 0; b < BLOCKS_PER_SECTOR; b++) {
      const block = s * BLOCKS_PER_SECTOR + b;
      buf.set(dumpData[block], block * BLOCK_SIZE);
    }
  }
  const blob = new Blob([buf], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `dump_${hexStrShort(currentUID || [0])}_${sectorCount}k.mfd`;
  a.click();
  URL.revokeObjectURL(url);
  toast(`Dump saved (${totalBytes} bytes)`);
}

function doLoadDump(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const data = new Uint8Array(reader.result);
    const blockSize = 16;
    const blocksPerSector = 4;
    const loadedSectors = Math.floor(data.length / (blocksPerSector * blockSize));

    for (let s = 0; s < loadedSectors && s < TOTAL_SECTORS_4K; s++) {
      for (let b = 0; b < blocksPerSector; b++) {
        const block = s * blocksPerSector + b;
        const offset = block * blockSize;
        if (offset + blockSize <= data.length) {
          dumpData[block] = data.slice(offset, offset + blockSize);
        }
      }
    }

    const totalBlocks = Math.min(Math.floor(data.length / blockSize), TOTAL_BLOCKS_4K);
    updateDumpTable();
    updateBlockInfo(parseInt($('selSector').value), parseInt($('selBlock').value), 0);

    if (totalBlocks >= 64) {
      $('selSector').value = 0;
      onSectorChange();
    }

    toast(`Loaded ${data.length} bytes (${loadedSectors} sectors) from ${file.name}`);
  };
  reader.readAsArrayBuffer(file);
  event.target.value = '';
}

async function doValueOp(op) {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  const s = parseInt($('selSector').value);
  const b = parseInt($('selBlock').value);
  const block = s * BLOCKS_PER_SECTOR + b;

  if (!(await authSector(s, block))) {
    toast('Auth failed for value op', false);
    return;
  }

  const amount = parseInt($('valueAmount').value) || 0;
  const buf = new ArrayBuffer(4);
  const view = new DataView(buf);
  view.setUint32(0, Math.abs(amount), true);
  const valueBytes = [
    new Uint8Array(buf)[0],
    new Uint8Array(buf)[1],
    new Uint8Array(buf)[2],
    new Uint8Array(buf)[3],
  ];

  try {
    let cmd;
    if (op === 'increment') cmd = [0xc1, block, ...valueBytes];
    else if (op === 'decrement') cmd = [0xc0, block, ...valueBytes];
    else if (op === 'restore') cmd = [0xc2, block, 0x00, 0x00, 0x00, 0x00];

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await inDataExchange(1, cmd, 2000);
        await sleep(20);
        await inDataExchange(1, [0xb0, block], 2000);
        break;
      } catch (e) {
        if (attempt < 2) {
          logInfo(`Value op: ${e.message}, retry ${attempt + 2}/3`);
          authedSector = -1;
          await sleep(50 * (attempt + 1));
          const keyType = $('selKeyType').value;
          const keyHex = keyType === 'B' ? sectorKeys[s].b : sectorKeys[s].a;
          await mfAuth(1, block, parseKey(keyHex), currentUID);
        } else {
          throw e;
        }
      }
    }

    toast(`${op} performed on block ${block}`);

    const data = await mfReadBlock(1, block);
    dumpData[block] = data;
    updateValueDisplay(data);
  } catch (e) {
    logErr('Value op error: ' + e.message);
    toast(op + ' failed: ' + e.message, false);
  }
}

async function doReadValue() {
  if (!cardPresent || !currentUID) {
    toast('No card detected', false);
    return;
  }
  const s = parseInt($('selSector').value);
  const b = parseInt($('selBlock').value);
  const block = s * BLOCKS_PER_SECTOR + b;

  if (!(await authSector(s, block))) {
    toast('Auth failed', false);
    return;
  }

  try {
    const data = await mfReadBlock(1, block);
    dumpData[block] = data;
    $('hexEditor').textContent = hexStr(data);
    updateAsciiPreview();
    updateValueDisplay(data);
  } catch (e) {
    toast('Read failed: ' + e.message, false);
  }
}

// ============================================================
//  Init
// ============================================================

updateKeyStorage();
updateDumpTable();

const sel = $('selSector');
for (let i = 0; i < 16; i++) {
  const o = document.createElement('option');
  o.value = i;
  o.textContent = i;
  sel.appendChild(o);
}

onSectorChange();
$('btnDump').disabled = true;
$('btnFindKeys').disabled = true;
$('btnCloneRead').disabled = true;
$('btnRelease').disabled = true;
$('btnAuth').disabled = true;
$('btnReadBlock').disabled = true;
$('btnWriteBlock').disabled = true;

window.addEventListener('beforeunload', () => {
  if (pn532.connected) doDisconnect();
});
