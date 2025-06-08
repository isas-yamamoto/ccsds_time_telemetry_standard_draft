import struct
import datetime
from datetime import timezone
import json

# --- Configuration based on Specification v2.1 ---

# Appendix B: Coding Scheme IDs
CODING_SCHEMES = {
    0x01: "RS_CONV",
    0x02: "TURBO",
    0x03: "LDPC",
}

# Appendix C: Standard, well-known Epochs
STANDARD_EPOCHS = {
    0x01: datetime.datetime(1980, 1, 6, 0, 0, 0, tzinfo=timezone.utc),  # GPS_EPOCH
}
# GPS Epoch is also a constant for GNSS calculations
GPS_EPOCH = STANDARD_EPOCHS[0x01]

# Appendix D: TLV Type IDs
TLV_TYPES = {
    0x01: "BITRATE_BPS",
    0x02: "ANTENNA_ID",
    0x03: "TX_PATH_ID",
    0x04: "GLOBAL_OFFSET_NS",
    0x05: "CODING_SCHEME_ID",
}
TLV_TYPES_REV = {v: k for k, v in TLV_TYPES.items()}


# --- CRC-16 Implementation ---
def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
    return crc & 0xFFFF


# --- Encoder Section ---


def _encode_tlv(param_type_id: int, value) -> bytes:
    # ... (Unchanged from previous version)
    if param_type_id == TLV_TYPES_REV["BITRATE_BPS"]:
        return struct.pack(">BB I", param_type_id, 4, value)
    elif param_type_id == TLV_TYPES_REV["ANTENNA_ID"]:
        return struct.pack(">BB B", param_type_id, 1, value)
    elif param_type_id == TLV_TYPES_REV["CODING_SCHEME_ID"]:
        return struct.pack(">BB B", param_type_id, 1, value)
    else:
        raise NotImplementedError(
            f"TLV encoder for type {param_type_id} not implemented."
        )


def _encode_tceh(tceh_params: list) -> bytes:
    # ... (Unchanged from previous version)
    tceh_bytes = b""
    for param in tceh_params:
        param_type_id = TLV_TYPES_REV.get(param["type"])
        if param_type_id is None:
            raise ValueError(f"Unknown TLV type: {param['type']}")
        tceh_bytes += _encode_tlv(param_type_id, param["value"])
    return tceh_bytes


def _encode_payload_jaxa_mission_time(
    payload_data: dict, user_defined_epochs: dict
) -> bytes:
    # ... (Unchanged from previous version)
    epoch_id, timestamp = payload_data["epoch_id"], payload_data["timestamp"]
    all_epochs = {**STANDARD_EPOCHS, **(user_defined_epochs or {})}
    base_epoch = all_epochs.get(epoch_id)
    if not base_epoch:
        raise ValueError(f"Epoch for epoch_id {epoch_id} is not defined.")
    delta = timestamp - base_epoch
    seconds_30bit = int(delta.total_seconds())
    microseconds_20bit = delta.microseconds
    if not (0 <= seconds_30bit < (1 << 30)):
        raise ValueError("Seconds out of range.")
    time_value = (seconds_30bit << 20) | microseconds_20bit
    packed_time_value = time_value << 14
    return struct.pack(
        ">B3xQIi",
        epoch_id,
        packed_time_value,
        payload_data["bitrate_bps"],
        payload_data["fixed_offset_ns"],
    )


# NEW: Encoder for GNSS payload
def _encode_payload_gnss_derived_time(payload_data: dict) -> bytes:
    """Encodes the payload for clock_source_id = 0x03."""
    timestamp = payload_data["timestamp"]
    if timestamp.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware.")

    delta = timestamp - GPS_EPOCH
    total_seconds = delta.total_seconds()

    gps_week_number = int(total_seconds // (7 * 24 * 3600))
    # Time of week in milliseconds
    time_of_week_ms = int((total_seconds % (7 * 24 * 3600)) * 1000)

    hdop_scaled = int(payload_data["hdop"] * 100)

    return struct.pack(
        ">HIBBH6x",  # H=week, I=ms, B=status, B=num_sv, H=hdop, 6x=reserved
        gps_week_number,
        time_of_week_ms,
        payload_data["status_flags"],
        payload_data["num_sv"],
        hdop_scaled,
    )


def encode_tcdu(
    scid: int,
    vcid: int,
    tceh_params: list,
    tts_data: dict,
    user_defined_epochs: dict = None,
) -> bytes:
    """Encodes a complete TCDU packet."""
    # ... (TCEH and TCDU Header encoding unchanged) ...
    tceh_bytes = _encode_tceh(tceh_params)
    tceh_length = len(tceh_bytes)
    if tceh_length > 255:
        raise ValueError("TCEH length > 255.")
    tcdu_header = struct.pack(">HB B 4x", scid, vcid, tceh_length)

    # UPDATED: Handle different payload types
    clock_source_id = tts_data["clock_source_id"]
    if clock_source_id == 0x10:
        tts_payload = _encode_payload_jaxa_mission_time(
            tts_data["payload"], user_defined_epochs
        )
    elif clock_source_id == 0x03:  # NEW
        tts_payload = _encode_payload_gnss_derived_time(tts_data["payload"])
    else:
        raise NotImplementedError(
            f"TTS payload encoder for clock_source_id {clock_source_id} not implemented."
        )

    # ... (TTS Header and final assembly unchanged) ...
    version, teh_flag = 1, 0
    header_byte0 = (version << 4) | (teh_flag << 3)
    tts_packet_length = 12 + 0 + len(tts_payload) + 2
    tts_header = struct.pack(
        ">BBHII",
        header_byte0,
        clock_source_id,
        tts_packet_length,
        tts_data["vc_frame_counter"],
        int(tts_data["payload"]["timestamp"].timestamp()),
    )
    tts_data_for_crc = tts_header + tts_payload
    crc = crc16_ccitt_false(tts_data_for_crc)
    tts_packet = tts_data_for_crc + struct.pack(">H", crc)
    return tcdu_header + tceh_bytes + tts_packet


# --- Decoder Section ---


def _decode_tlv(tlv_bytes: bytes) -> tuple:
    # ... (Unchanged)
    tlv_type, length = struct.unpack_from(">BB", tlv_bytes)
    value_bytes = tlv_bytes[2 : 2 + length]
    param_name = TLV_TYPES.get(tlv_type, f"UNKNOWN_TYPE_{hex(tlv_type)}")
    if param_name == "BITRATE_BPS" and length == 4:
        value = struct.unpack(">I", value_bytes)[0]
    elif param_name in ["ANTENNA_ID", "CODING_SCHEME_ID"] and length == 1:
        value = struct.unpack(">B", value_bytes)[0]
    else:
        value = value_bytes.hex(" ")
    return param_name, value, 2 + length


def _decode_tceh(tceh_bytes: bytes) -> list:
    # ... (Unchanged)
    params = []
    processed_bytes = 0
    while processed_bytes < len(tceh_bytes):
        name, value, consumed = _decode_tlv(tceh_bytes[processed_bytes:])
        params.append({"type": name, "value": value})
        processed_bytes += consumed
    return params


def _decode_payload_jaxa_mission_time(
    payload_bytes: bytes, user_defined_epochs: dict
) -> dict:
    # ... (Unchanged)
    epoch_id, packed, bitrate, offset = struct.unpack(">B3xQIi", payload_bytes)
    time_val = packed >> 14
    sec, usec = time_val >> 20, time_val & 0xFFFFF
    all_epochs = {**STANDARD_EPOCHS, **(user_defined_epochs or {})}
    base_epoch = all_epochs.get(epoch_id)
    if not base_epoch:
        raise ValueError(f"Epoch {epoch_id} not defined.")
    recon_time = base_epoch + datetime.timedelta(seconds=sec, microseconds=usec)
    return {
        "reconstructed_utc": recon_time.isoformat(),
        "epoch_id": epoch_id,
        "bitrate_bps": bitrate,
        "fixed_offset_ns": offset,
    }


# NEW: Decoder for GNSS payload
def _decode_payload_gnss_derived_time(payload_bytes: bytes) -> dict:
    """Decodes the payload for clock_source_id = 0x03."""
    week, ms, status, num_sv, hdop_scaled = struct.unpack(">HIBBH6x", payload_bytes)

    seconds_since_epoch = (week * 7 * 24 * 3600) + (ms / 1000.0)
    reconstructed_time = GPS_EPOCH + datetime.timedelta(seconds=seconds_since_epoch)

    return {
        "reconstructed_utc": reconstructed_time.isoformat(),
        "gps_week": week,
        "time_of_week_ms": ms,
        "status_flags": hex(status),
        "num_sv": num_sv,
        "hdop": hdop_scaled / 100.0,
    }


def decode_tcdu(tcdu_bytes: bytes, user_defined_epochs: dict = None) -> dict:
    # ... (TCDU header and TCEH decoding unchanged) ...
    scid, vcid, tceh_length = struct.unpack_from(">HB B", tcdu_bytes)
    tceh_start, tceh_end = 8, 8 + tceh_length
    decoded_tceh_params = _decode_tceh(tcdu_bytes[tceh_start:tceh_end])

    # ... (TTS packet isolation and CRC check unchanged) ...
    tts_packet_bytes = tcdu_bytes[tceh_end:]
    tts_header = struct.unpack_from(">BBHII", tts_packet_bytes)
    if len(tts_packet_bytes) != tts_header[2]:
        raise ValueError("TTS length mismatch.")
    if (
        crc16_ccitt_false(tts_packet_bytes[:-2])
        != struct.unpack(">H", tts_packet_bytes[-2:])[0]
    ):
        raise ValueError("CRC fail.")

    # UPDATED: Handle different payload types
    clock_source_id = tts_header[1]
    tts_payload_bytes = tts_packet_bytes[12:-2]

    if clock_source_id == 0x10:
        decoded_payload = _decode_payload_jaxa_mission_time(
            tts_payload_bytes, user_defined_epochs
        )
    elif clock_source_id == 0x03:  # NEW
        decoded_payload = _decode_payload_gnss_derived_time(tts_payload_bytes)
    else:
        raise NotImplementedError(
            f"TTS payload decoder for clock_source_id {clock_source_id} not implemented."
        )

    # ... (Result assembly unchanged) ...
    return {
        "tcdu_header": {"scid": scid, "vcid": vcid},
        "tceh_params": decoded_tceh_params,
        "tts": {
            "vc_frame_counter": tts_header[3],
            "clock_source_id": clock_source_id,
            "crc_ok": True,
            "payload": decoded_payload,
        },
    }


# --- Example Usage ---
if __name__ == "__main__":
    # --- Example 1: JAXA Mission Time (unchanged from previous version) ---
    # ... (You can keep the previous JAXA time example here if you wish) ...

    print("\n" + "=" * 50 + "\n")

    # --- Example 2: GNSS-Derived Time ---
    print("--- Example 2: GNSS-Derived Time (clock_source_id = 0x03) ---")

    utc_now = datetime.datetime.now(timezone.utc)

    # Optional parameters for the TCEH
    tceh_for_gnss = [
        {"type": "BITRATE_BPS", "value": 1000000},
        {"type": "CODING_SCHEME_ID", "value": 0x01},  # RS_CONV
    ]

    # Payload for the GNSS clock source
    # Example status_flags: SYNC_LOCKED (10), NOT_IN_HOLDOVER (00), Normal (0) -> 1000 0000 -> 0x80
    gnss_payload_to_encode = {
        "timestamp": utc_now,
        "status_flags": 0b10000000,
        "num_sv": 12,
        "hdop": 0.95,
    }

    tts_for_gnss = {
        "clock_source_id": 0x03,
        "vc_frame_counter": 54321,
        "payload": gnss_payload_to_encode,
    }

    print("Input Data:")
    print(
        json.dumps({"tceh": tceh_for_gnss, "tts": tts_for_gnss}, indent=2, default=str)
    )

    # Encode the packet
    encoded_gnss_packet = encode_tcdu(
        scid=0x3C4D, vcid=5, tceh_params=tceh_for_gnss, tts_data=tts_for_gnss
    )

    print(f"\nEncoded TCDU Packet ({len(encoded_gnss_packet)} bytes):")
    print(encoded_gnss_packet.hex(" "))

    print("\n--- DECODING GNSS Packet ---")

    # Decode the packet
    try:
        decoded_gnss_data = decode_tcdu(encoded_gnss_packet)
        print("Decoded Data:")
        print(json.dumps(decoded_gnss_data, indent=2))

        # Verification
        original_time_str = utc_now.isoformat(timespec="microseconds")
        reconstructed_time_str = decoded_gnss_data["tts"]["payload"][
            "reconstructed_utc"
        ]
        print(f"\nOriginal UTC:       {original_time_str}")
        print(f"Reconstructed UTC:  {reconstructed_time_str}")

        # Note: a small difference can occur due to floating point precision of ms
        original_dt = datetime.datetime.fromisoformat(original_time_str)
        reconstructed_dt = datetime.datetime.fromisoformat(reconstructed_time_str)
        time_diff = abs((original_dt - reconstructed_dt).total_seconds())

        if time_diff < 0.001:
            print("Time reconstruction successful (within 1ms tolerance)!")
        else:
            print(f"Time reconstruction difference is too large: {time_diff}s")

    except (ValueError, NotImplementedError) as e:
        print(f"Decoding failed: {e}")
