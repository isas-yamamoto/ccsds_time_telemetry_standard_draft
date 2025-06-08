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

# Appendix D: TLV Type IDs
TLV_TYPES = {
    0x01: "BITRATE_BPS",
    0x02: "ANTENNA_ID",
    0x03: "TX_PATH_ID",
    0x04: "GLOBAL_OFFSET_NS",
    0x05: "CODING_SCHEME_ID",
}
# Reverse map for encoding
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
    """Encodes a single TLV field."""
    if param_type_id == TLV_TYPES_REV["BITRATE_BPS"]:
        # Type 0x01, Length 4, Value (u_int32)
        return struct.pack(">BB I", param_type_id, 4, value)
    elif param_type_id == TLV_TYPES_REV["ANTENNA_ID"]:
        # Type 0x02, Length 1, Value (u_int8)
        return struct.pack(">BB B", param_type_id, 1, value)
    elif param_type_id == TLV_TYPES_REV["CODING_SCHEME_ID"]:
        # Type 0x05, Length 1, Value (u_int8)
        return struct.pack(">BB B", param_type_id, 1, value)
    else:
        raise NotImplementedError(
            f"TLV encoder for type {param_type_id} not implemented."
        )


def _encode_tceh(tceh_params: list) -> bytes:
    """Encodes a list of parameters into a TCEH byte string."""
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
    """Encodes the payload for clock_source_id = 0x10."""
    epoch_id = payload_data["epoch_id"]
    timestamp = payload_data["timestamp"]

    all_epochs = STANDARD_EPOCHS.copy()
    if user_defined_epochs:
        all_epochs.update(user_defined_epochs)

    base_epoch = all_epochs.get(epoch_id)
    if not base_epoch:
        raise ValueError(f"Epoch for epoch_id {epoch_id} is not defined.")

    delta = timestamp - base_epoch
    seconds_30bit = int(delta.total_seconds())
    microseconds_20bit = delta.microseconds

    if not (0 <= seconds_30bit < (1 << 30)):
        raise ValueError("Seconds counter out of 30-bit range.")

    time_value = (seconds_30bit << 20) | microseconds_20bit
    packed_time_value = time_value << 14

    return struct.pack(
        ">B3xQIi",
        epoch_id,
        packed_time_value,
        payload_data["bitrate_bps"],
        payload_data["fixed_offset_ns"],
    )


def encode_tcdu(
    scid: int,
    vcid: int,
    tceh_params: list,
    tts_data: dict,
    user_defined_epochs: dict = None,
) -> bytes:
    """
    Encodes a complete TCDU packet based on the provided data.
    """
    # 1. Encode TCEH
    tceh_bytes = _encode_tceh(tceh_params)
    tceh_length = len(tceh_bytes)
    if tceh_length > 255:
        raise ValueError("TCEH length cannot exceed 255 bytes.")

    # 2. Encode TCDU Header
    tcdu_header = struct.pack(">HB B 4x", scid, vcid, tceh_length)

    # 3. Encode TTS Payload
    clock_source_id = tts_data["clock_source_id"]
    if clock_source_id == 0x10:
        tts_payload = _encode_payload_jaxa_mission_time(
            tts_data["payload"], user_defined_epochs or {}
        )
    else:
        raise NotImplementedError(
            f"TTS payload encoder for clock_source_id {clock_source_id} not implemented."
        )

    # 4. Encode TTS Header
    # Assuming no TEH for this example (TEH_flag = 0)
    version = 1
    teh_flag = 0
    header_byte0 = (version << 4) | (teh_flag << 3)

    # Header(12) + TEH(0) + Payload(N) + CRC(2)
    tts_packet_length = 12 + 0 + len(tts_payload) + 2

    tts_header = struct.pack(
        ">BBHII",
        header_byte0,
        clock_source_id,
        tts_packet_length,
        tts_data["vc_frame_counter"],
        int(
            tts_data["payload"]["timestamp"].timestamp()
        ),  # Use payload timestamp for generic sec
    )

    # 5. Calculate CRC and assemble TTS Packet
    tts_data_for_crc = tts_header + tts_payload
    crc = crc16_ccitt_false(tts_data_for_crc)
    tts_packet = tts_data_for_crc + struct.pack(">H", crc)

    # 6. Assemble final TCDU
    return tcdu_header + tceh_bytes + tts_packet


# --- Decoder Section ---


def _decode_tlv(tlv_bytes: bytes) -> tuple:
    """Decodes a single TLV field from the start of a byte string."""
    tlv_type, length = struct.unpack_from(">BB", tlv_bytes)
    value_bytes = tlv_bytes[2 : 2 + length]

    param_name = TLV_TYPES.get(tlv_type, f"UNKNOWN_TYPE_{hex(tlv_type)}")

    # Interpret value based on type
    if param_name == "BITRATE_BPS" and length == 4:
        value = struct.unpack(">I", value_bytes)[0]
    elif param_name in ["ANTENNA_ID", "CODING_SCHEME_ID"] and length == 1:
        value = struct.unpack(">B", value_bytes)[0]
    else:
        value = value_bytes.hex(
            " "
        )  # Default to hex string for unknown/unhandled types

    return (
        param_name,
        value,
        2 + length,
    )  # Return name, value, and total consumed length


def _decode_tceh(tceh_bytes: bytes) -> list:
    """Decodes a TCEH byte string into a list of parameters."""
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
    """Decodes the payload for clock_source_id = 0x10."""
    epoch_id, packed_time_value, bitrate_bps, fixed_offset_ns = struct.unpack(
        ">B3xQIi", payload_bytes
    )

    time_value = packed_time_value >> 14
    seconds_30bit = time_value >> 20
    microseconds_20bit = time_value & 0xFFFFF

    all_epochs = STANDARD_EPOCHS.copy()
    if user_defined_epochs:
        all_epochs.update(user_defined_epochs)

    base_epoch = all_epochs.get(epoch_id)
    if not base_epoch:
        raise ValueError(f"Epoch for epoch_id {epoch_id} is not defined.")

    reconstructed_time = base_epoch + datetime.timedelta(
        seconds=seconds_30bit, microseconds=microseconds_20bit
    )

    return {
        "reconstructed_utc": reconstructed_time.isoformat(),
        "epoch_id": epoch_id,
        "bitrate_bps": bitrate_bps,
        "fixed_offset_ns": fixed_offset_ns,
    }


def decode_tcdu(tcdu_bytes: bytes, user_defined_epochs: dict = None) -> dict:
    """Decodes a complete TCDU packet into a dictionary."""
    # 1. Decode TCDU Header
    scid, vcid, tceh_length = struct.unpack_from(">HB B", tcdu_bytes)

    # 2. Decode TCEH
    tceh_start = 8
    tceh_end = tceh_start + tceh_length
    tceh_bytes = tcdu_bytes[tceh_start:tceh_end]
    decoded_tceh_params = _decode_tceh(tceh_bytes)

    # 3. Isolate and validate TTS Packet
    tts_packet_bytes = tcdu_bytes[tceh_end:]
    tts_header = struct.unpack_from(">BBHII", tts_packet_bytes)
    packet_length_in_header = tts_header[2]

    if len(tts_packet_bytes) != packet_length_in_header:
        raise ValueError("TTS packet length mismatch.")

    # 4. Verify CRC
    tts_data_for_crc = tts_packet_bytes[:-2]
    expected_crc = struct.unpack(">H", tts_packet_bytes[-2:])[0]
    if crc16_ccitt_false(tts_data_for_crc) != expected_crc:
        raise ValueError("TTS CRC check failed.")

    # 5. Decode TTS Header and Payload
    clock_source_id = tts_header[1]
    vc_frame_counter = tts_header[3]

    tts_payload_bytes = tts_packet_bytes[12:-2]  # 12 is TTS header size

    if clock_source_id == 0x10:
        decoded_payload = _decode_payload_jaxa_mission_time(
            tts_payload_bytes, user_defined_epochs or {}
        )
    else:
        raise NotImplementedError(
            f"TTS payload decoder for clock_source_id {clock_source_id} not implemented."
        )

    # 6. Assemble final result
    return {
        "tcdu_header": {"scid": scid, "vcid": vcid},
        "tceh_params": decoded_tceh_params,
        "tts": {
            "vc_frame_counter": vc_frame_counter,
            "clock_source_id": clock_source_id,
            "crc_ok": True,
            "payload": decoded_payload,
        },
    }


# --- Example Usage ---
if __name__ == "__main__":
    # Define a user-specific epoch for a hypothetical mission
    my_mission_epochs = {
        0x02: datetime.datetime(
            2013, 1, 1, 0, 0, 0, tzinfo=timezone.utc
        )  # User Defined Epoch 1
    }

    # -- 1. Define the data for a complex packet --
    utc_now = datetime.datetime.now(timezone.utc)

    # Optional parameters to be included in the TCEH
    tceh_to_encode = [
        {"type": "BITRATE_BPS", "value": 8000000},
        {"type": "CODING_SCHEME_ID", "value": 0x03},  # LDPC
        {"type": "ANTENNA_ID", "value": 0b00000001},  # B-System, HGA
    ]

    # TTS packet data, including the payload for clock source 0x10
    tts_to_encode = {
        "clock_source_id": 0x10,
        "vc_frame_counter": 12345,
        "payload": {
            "epoch_id": 0x02,  # Using the user-defined epoch
            "timestamp": utc_now,
            "bitrate_bps": 8000000,  # This can be redundant, but part of the 0x10 spec
            "fixed_offset_ns": -250,
        },
    }

    print("--- ENCODING ---")
    print("Input Data:")
    print(
        json.dumps(
            {"tceh": tceh_to_encode, "tts": tts_to_encode}, indent=2, default=str
        )
    )

    # -- 2. Encode the packet --
    encoded_packet = encode_tcdu(
        scid=0x1A2B,
        vcid=3,
        tceh_params=tceh_to_encode,
        tts_data=tts_to_encode,
        user_defined_epochs=my_mission_epochs,
    )

    print(f"\nEncoded TCDU Packet ({len(encoded_packet)} bytes):")
    print(encoded_packet.hex(" "))

    print("\n--- DECODING ---")

    # -- 3. Decode the packet --
    try:
        decoded_data = decode_tcdu(
            encoded_packet, user_defined_epochs=my_mission_epochs
        )
        print("Decoded Data:")
        print(json.dumps(decoded_data, indent=2))

        # -- 4. Verification --
        original_time_str = utc_now.isoformat(timespec="microseconds")
        reconstructed_time_str = decoded_data["tts"]["payload"]["reconstructed_utc"]
        print(f"\nOriginal UTC:       {original_time_str}")
        print(f"Reconstructed UTC:  {reconstructed_time_str}")
        assert original_time_str == reconstructed_time_str
        print("Time reconstruction successful!")

    except (ValueError, NotImplementedError) as e:
        print(f"Decoding failed: {e}")
