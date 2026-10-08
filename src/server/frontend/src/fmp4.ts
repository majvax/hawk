// A minimal fragmented-MP4 muxer for the one H.264 track the machine
// streams, so the stream can play through Media Source Extensions on
// browsers without a WebCodecs H.264 decoder (Firefox for Android). Each
// access unit becomes its own fragment (moof + mdat), appended as it
// arrives.

const NAL_SPS = 7;
const NAL_PPS = 8;
const NAL_AUD = 9;

// The track's clock: microseconds, the unit the machine stamps frames in.
export const TIMESCALE = 1_000_000;

// Splits an Annex-B access unit on its 00 00 01 / 00 00 00 01 start codes.
export function splitNalUnits(data: Uint8Array): Uint8Array[] {
  const units: Uint8Array[] = [];
  let start = -1;
  let i = 0;
  while (i + 2 < data.length) {
    if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1) {
      if (start >= 0) {
        // A four-byte start code leaves its leading zero on the unit before.
        let end = i;
        if (end > start && data[end - 1] === 0) end -= 1;
        units.push(data.subarray(start, end));
      }
      i += 3;
      start = i;
    } else {
      i += 1;
    }
  }
  if (start >= 0 && start < data.length) units.push(data.subarray(start));
  return units.filter((unit) => unit.length > 0);
}

function nalType(unit: Uint8Array): number {
  return (unit[0] ?? 0) & 0x1f;
}

export interface ParameterSets {
  sps: Uint8Array;
  pps: Uint8Array;
}

// The SPS and PPS a keyframe carries inline, or null if it lacks either.
export function findParameterSets(units: Uint8Array[]): ParameterSets | null {
  const sps = units.find((unit) => nalType(unit) === NAL_SPS);
  const pps = units.find((unit) => nalType(unit) === NAL_PPS);
  return sps !== undefined && pps !== undefined ? { sps, pps } : null;
}

// The access unit as an MP4 sample: each NAL behind a 4-byte length, with
// the parameter sets (they live in avcC) and access unit delimiters left out.
export function toAvcSample(units: Uint8Array[]): Uint8Array {
  const kept = units.filter((unit) => {
    const type = nalType(unit);
    return type !== NAL_SPS && type !== NAL_PPS && type !== NAL_AUD;
  });
  const sample = new Uint8Array(kept.reduce((size, unit) => size + 4 + unit.length, 0));
  const view = new DataView(sample.buffer);
  let offset = 0;
  for (const unit of kept) {
    view.setUint32(offset, unit.length);
    sample.set(unit, offset + 4);
    offset += 4 + unit.length;
  }
  return sample;
}

// "avc1.PPCCLL" from the SPS's profile, constraint flags and level.
export function codecString(sps: Uint8Array): string {
  const hex = (byte: number | undefined): string => (byte ?? 0).toString(16).padStart(2, "0").toUpperCase();
  return `avc1.${hex(sps[1])}${hex(sps[2])}${hex(sps[3])}`;
}

// Reads an SPS's RBSP bit by bit, emulation-prevention bytes removed.
class BitReader {
  private readonly bytes: Uint8Array;
  private bit = 0;

  constructor(nal: Uint8Array) {
    const bytes: number[] = [];
    for (let i = 0; i < nal.length; i++) {
      const byte = nal[i] ?? 0;
      if (byte === 3 && i >= 2 && nal[i - 1] === 0 && nal[i - 2] === 0) continue;
      bytes.push(byte);
    }
    this.bytes = Uint8Array.from(bytes);
  }

  u(count: number): number {
    let value = 0;
    for (let i = 0; i < count; i++) {
      const byte = this.bytes[this.bit >> 3] ?? 0;
      value = (value << 1) | ((byte >> (7 - (this.bit & 7))) & 1);
      this.bit += 1;
    }
    return value >>> 0;
  }

  ue(): number {
    let zeros = 0;
    while (this.u(1) === 0 && zeros < 32) zeros += 1;
    return (2 ** zeros - 1) + this.u(zeros);
  }

  se(): number {
    const value = this.ue();
    return value & 1 ? (value + 1) / 2 : -(value / 2);
  }
}

// The picture size an SPS describes, after cropping.
export function spsDimensions(sps: Uint8Array): { width: number; height: number } {
  const reader = new BitReader(sps);
  reader.u(8); // NAL header
  const profile = reader.u(8);
  reader.u(16); // constraint flags, level
  reader.ue(); // seq_parameter_set_id

  let chromaFormat = 1;
  let separateColourPlanes = 0;
  if ([100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135].includes(profile)) {
    chromaFormat = reader.ue();
    if (chromaFormat === 3) separateColourPlanes = reader.u(1);
    reader.ue(); // bit_depth_luma_minus8
    reader.ue(); // bit_depth_chroma_minus8
    reader.u(1); // qpprime_y_zero_transform_bypass_flag
    if (reader.u(1)) {
      // seq_scaling_matrix_present_flag: skip every list that is present.
      for (let i = 0; i < (chromaFormat === 3 ? 12 : 8); i++) {
        if (!reader.u(1)) continue;
        const size = i < 6 ? 16 : 64;
        let last = 8;
        let next = 8;
        for (let j = 0; j < size; j++) {
          if (next !== 0) next = (last + reader.se() + 256) % 256;
          last = next === 0 ? last : next;
        }
      }
    }
  }

  reader.ue(); // log2_max_frame_num_minus4
  const pocType = reader.ue();
  if (pocType === 0) {
    reader.ue(); // log2_max_pic_order_cnt_lsb_minus4
  } else if (pocType === 1) {
    reader.u(1); // delta_pic_order_always_zero_flag
    reader.se(); // offset_for_non_ref_pic
    reader.se(); // offset_for_top_to_bottom_field
    const cycle = reader.ue();
    for (let i = 0; i < cycle; i++) reader.se();
  }
  reader.ue(); // max_num_ref_frames
  reader.u(1); // gaps_in_frame_num_value_allowed_flag
  const widthMbs = reader.ue() + 1;
  const heightMapUnits = reader.ue() + 1;
  const frameMbsOnly = reader.u(1);
  if (!frameMbsOnly) reader.u(1); // mb_adaptive_frame_field_flag
  reader.u(1); // direct_8x8_inference_flag

  let width = widthMbs * 16;
  let height = (2 - frameMbsOnly) * heightMapUnits * 16;
  if (reader.u(1)) {
    // frame_cropping_flag: offsets are in chroma sample units.
    const left = reader.ue();
    const right = reader.ue();
    const top = reader.ue();
    const bottom = reader.ue();
    const chroma = separateColourPlanes ? 0 : chromaFormat;
    const cropX = chroma === 1 || chroma === 2 ? 2 : 1;
    const cropY = (chroma === 1 ? 2 : 1) * (2 - frameMbsOnly);
    width -= cropX * (left + right);
    height -= cropY * (top + bottom);
  }
  return { width, height };
}

// --- Boxes ---------------------------------------------------------------

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function box(type: string, ...payload: Uint8Array[]): Uint8Array {
  const body = concat(payload);
  const out = new Uint8Array(8 + body.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, out.length);
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(body, 8);
  return out;
}

// Big-endian fields, written in order.
function fields(...values: Array<[bits: 8 | 16 | 32 | 64, value: number]>): Uint8Array {
  const out = new Uint8Array(values.reduce((size, [bits]) => size + bits / 8, 0));
  const view = new DataView(out.buffer);
  let offset = 0;
  for (const [bits, value] of values) {
    if (bits === 8) view.setUint8(offset, value);
    else if (bits === 16) view.setUint16(offset, value);
    else if (bits === 32) view.setUint32(offset, value >>> 0);
    else view.setBigUint64(offset, BigInt(Math.round(value)));
    offset += bits / 8;
  }
  return out;
}

function ascii(text: string): Uint8Array {
  return Uint8Array.from(text, (char) => char.charCodeAt(0));
}

const zeros = (count: number): Uint8Array => new Uint8Array(count);

// The unity transform every header box carries.
const MATRIX = fields([32, 0x00010000], [32, 0], [32, 0], [32, 0], [32, 0x00010000], [32, 0], [32, 0], [32, 0], [32, 0x40000000]);

// ftyp + moov for one H.264 track of the given parameter sets.
export function initSegment({ sps, pps }: ParameterSets): Uint8Array {
  const { width, height } = spsDimensions(sps);

  const ftyp = box("ftyp", ascii("isom"), fields([32, 0x200]), ascii("isomiso6avc1mp41"));
  const mvhd = box(
    "mvhd",
    fields([32, 0], [32, 0], [32, 0], [32, TIMESCALE], [32, 0], [32, 0x00010000], [16, 0x0100]),
    zeros(10),
    MATRIX,
    zeros(24),
    fields([32, 2]), // next_track_ID
  );
  const tkhd = box(
    "tkhd",
    fields([32, 0x00000003], [32, 0], [32, 0], [32, 1], [32, 0], [32, 0]),
    zeros(8),
    fields([16, 0], [16, 0], [16, 0], [16, 0]),
    MATRIX,
    fields([32, width << 16], [32, height << 16]),
  );
  const mdhd = box("mdhd", fields([32, 0], [32, 0], [32, 0], [32, TIMESCALE], [32, 0], [16, 0x55c4], [16, 0]));
  const hdlr = box("hdlr", fields([32, 0], [32, 0]), ascii("vide"), zeros(12), ascii("VideoHandler\0"));

  const avcC = box(
    "avcC",
    fields([8, 1], [8, sps[1] ?? 0], [8, sps[2] ?? 0], [8, sps[3] ?? 0], [8, 0xff], [8, 0xe1], [16, sps.length]),
    sps,
    fields([8, 1], [16, pps.length]),
    pps,
  );
  const avc1 = box(
    "avc1",
    zeros(6),
    fields([16, 1], [16, 0], [16, 0]), // data_reference_index, pre_defined, reserved
    zeros(12),
    fields([16, width], [16, height], [32, 0x00480000], [32, 0x00480000], [32, 0], [16, 1]),
    zeros(32), // compressorname
    fields([16, 0x0018], [16, 0xffff]),
    avcC,
  );
  const stbl = box(
    "stbl",
    box("stsd", fields([32, 0], [32, 1]), avc1),
    box("stts", fields([32, 0], [32, 0])),
    box("stsc", fields([32, 0], [32, 0])),
    box("stsz", fields([32, 0], [32, 0], [32, 0])),
    box("stco", fields([32, 0], [32, 0])),
  );
  const minf = box(
    "minf",
    box("vmhd", fields([32, 1], [16, 0], [16, 0], [16, 0], [16, 0])),
    box("dinf", box("dref", fields([32, 0], [32, 1]), box("url ", fields([32, 1])))),
    stbl,
  );
  const trak = box("trak", tkhd, box("mdia", mdhd, hdlr, minf));
  const mvex = box("mvex", box("trex", fields([32, 0], [32, 1], [32, 1], [32, 0], [32, 0], [32, 0])));
  return concat([ftyp, box("moov", mvhd, trak, mvex)]);
}

// One fragment holding one sample: moof + mdat.
export function mediaSegment(
  sequence: number,
  decodeTime: number,
  duration: number,
  isKeyframe: boolean,
  sample: Uint8Array,
): Uint8Array {
  // sample_depends_on = 2 for a sync sample; depends_on = 1 + non-sync otherwise.
  const sampleFlags = isKeyframe ? 0x02000000 : 0x01010000;
  const trun = box(
    "trun",
    fields([32, 0x00000701], [32, 1], [32, 0], [32, duration], [32, sample.length], [32, sampleFlags]),
  );
  const moof = box(
    "moof",
    box("mfhd", fields([32, 0], [32, sequence])),
    box(
      "traf",
      box("tfhd", fields([32, 0x00020000], [32, 1])), // default-base-is-moof
      box("tfdt", fields([32, 0x01000000], [64, decodeTime])),
      trun,
    ),
  );
  // trun ends the moof; its data_offset (to the sample, past mdat's header)
  // sits 16 bytes in.
  new DataView(moof.buffer).setUint32(moof.length - trun.length + 16, moof.length + 8);
  return concat([moof, box("mdat", sample)]);
}
