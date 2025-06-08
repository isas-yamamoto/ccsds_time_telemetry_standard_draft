# CCSDS Time Correlation Data Unit (TCDU) Specification

**Version: 1.0**  
**Date: 2025-06-08**


## 1. Introduction

### 1.1 Purpose and Scope

This document defines a standard format for a **Time Correlation Data Unit (TCDU)**. The TCDU is designed to provide a precise correlation between a spacecraft's telemetry transfer frame and a high-precision timestamp.

The TCDU encapsulates a **Time Telemetry Standard (TTS) packet**, which contains detailed timestamp information from various onboard clock sources. This hierarchical structure ensures that the context (i.e., which frame is being time-tagged) is cleanly separated from the detailed time data itself, providing a robust and scalable solution for high-precision timekeeping in space missions.

### 1.2 Document Structure

*   **Section 2:** Defines the overall structure of the TCDU.
*   **Section 3:** Defines the structure of the encapsulated TTS Packet.
*   **Appendix A:** Lists assigned Clock Source IDs for the TTS packet.
*   **Appendix B:** Lists assigned Coding Scheme IDs.
*   **Appendix C:** Lists assigned Epoch IDs.
*   **Appendix D:** Lists assigned TLV Type IDs for the TCEH.

### 1.3 Conventions and Definitions

*   All multi-byte integer values shall be encoded in **Big-Endian** format.
*   **Bit Numbering:** Within any multi-bit field, bits are numbered from left to right, starting with bit 0 for the **Most Significant Bit (MSB)**.
*   **TCDU:** The top-level data unit defined in this document.
*   **TTS Packet:** The encapsulated time telemetry data unit.
*   **Reserved Fields:** All fields marked as "Reserved" shall be set to zero by the transmitter and must be ignored by the receiver.

## 2. Time Correlation Data Unit (TCDU) Structure

The TCDU is a variable-length data unit. Its structure is composed of three main parts: a fixed-size TCDU Header, a variable-size optional TCDU Context Extension Header (TCEH), and the variable-size TTS Packet.

| Block | Size (Bytes) | Description |
| :--- | :---: | :--- |
| **TCDU Header** | 8 | Contains fundamental information and the length of the TCEH. |
| **[Optional] TCDU Context Ext. Hdr (TCEH)** | Variable (M) | A container for zero or more TLV-encoded optional parameters. |
| **TTS Packet** | Variable (P) | The encapsulated Time Telemetry Standard (TTS) Packet. |

### 2.1 TCDU Header

The TCDU Header is a fixed 8-byte block.

| Offset (Bytes) | Field Name | Size (Bytes) | Data Type | Description |
| :---: | :--- | :---: | :--- | :--- |
| 0 | `scid` | 2 | `u_int16` | **Spacecraft Identifier.** |
| 2 | `vcid` | 1 | `u_int8` | **Virtual Channel Identifier.** (Note: Typically only bits 0-2 are used.) |
| 3 | `tceh_length` | 1 | `u_int8` | **The length of the TCDU Context Extension Header (TCEH) in bytes.** If `0`, the TCEH is absent. |
| 4 | `reserved` | 4 | `u_int32` | Reserved for future use. Shall be `0`. |
| 8 | **Start of TCEH (if `tceh_length` > 0)** or **Start of TTS Packet (if `tceh_length` == 0)** |


### 2.2 TCDU Context Extension Header (TCEH) Definition

The TCEH is a variable-length section that acts as a container for a series of TLV (Type-Length-Value) encoded optional parameters. Its total length is specified by the `tceh_length` field in the TCDU Header.

**Structure:** A sequence of zero or more TLV fields.

```
| TLV 1 | TLV 2 | ... | TLV n |
```

The sum of the sizes of all TLV fields must equal `tceh_length`.

### 2.3 TLV (Type-Length-Value) Field Structure

Each optional parameter is encoded as a TLV field.

| Part | Size (Bytes) | Data Type | Description |
| :---: | :---: | :---: | :--- |
| **Type (T)** | 1 | `u_int8` | An identifier for the parameter type. See Appendix D. |
| **Length (L)** | 1 | `u_int8` | The length of the following `Value` field in bytes. |
| **Value (V)** | Variable (L) | `bytes` | The actual data for the parameter. Its interpretation depends on the `Type`. |

A decoder must be able to parse a sequence of TLVs by reading T, then L, then L bytes of V, and then repeating the process until the entire TCEH (of `tceh_length` bytes) has been consumed. If a decoder encounters a `Type` it does not recognize, it must use the `Length` field to skip over the `Value` field and proceed to the next TLV.

## 3. Time Telemetry Standard (TTS) Packet Structure

The TTS Packet is the core payload of the TCDU.

### 3.1 TTS Packet Overview

| Block | Size (Bytes) | Description |
| :--- | :---: | :--- |
| **TTS Common Header** | 12 | Contains fundamental information about the TTS packet. |
| **[Optional] Timestamp Ext. Hdr** | 4 (if present) | Contains the sub-second part of the timestamp. |
| **Data Payload** | Variable (N) | Contains data specific to the clock source. |
| **Checksum** | 2 | A CRC-16 checksum for the **TTS Packet only**. |
| **Total TTS Packet Size** | 14+N or 18+N | The `packet_length` field within the TTS Common Header reflects this size. |

### 3.2 TTS Common Header

| Offset (Bytes) | Field Name | Size (Bits) | Data Type | Description |
| :---: | :--- | :---: | :--- | :--- |
| 0 | `version` | 4 | `u_int4` | TTS format version (Bits 0-3). Initial version is `0x1`. |
| 0 | `TEH_flag` | 1 | `u_int1` | Timestamp Extension Header Flag (Bit 4). `1` if TEH is present. |
| 0 | `reserved` | 3 | `u_int3` | Reserved (Bits 5-7). |
| 1 | `clock_source_id` | 8 | `u_int8` | Identifier for the clock source. See Appendix A. |
| 2 | `packet_length` | 16 | `u_int16` | The total length of this TTS packet. |
| 4 | `vc_frame_counter` | 32 | `u_int32` | **Virtual Channel Frame Counter.** The sequence count of the time-tagged frame. |
| 8 | `timestamp_sec` | 32 | `u_int32` | **Timestamp (Seconds).** The integer part of the time value. |

**Byte 0 Bitfield Structure (MSB=0)**

```
  Bit: | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
       +---------------+---+-----------+
Value: |     version   |TEH| reserved  |
       +---------------+---+-----------+
                         ^
                         TEH_flag
```

### 3.3 Timestamp Extension Header (TEH) Definition

*(Present if and only if `TEH_flag` is 1)*

| Offset (Bytes) | Field Name | Size (Bytes) | Data Type | Unit / Description |
| :---: | :--- | :---: | :--- | :--- |
| 0 | `subsecond_fraction` | 4 | `u_int32` | **Fraction of Second.** Where `2^32` represents one second. Provides ~232 picosecond resolution. |

### 3.4 Data Payload Definition

The structure of the Data Payload is determined by the `clock_source_id` field in the TTS Common Header.

#### 3.4.1 Simple Counter (`clock_source_id = 0x01`)
This payload provides a flexible way to transmit a free-running counter value of variable length.

*   **Payload Length (N):** `1 + counter_size` bytes (Variable)

| Offset (Bytes) | Field Name | Size (Bytes) | Data Type | Description |
| :---: | :--- | :---: | :--- | :--- |
| 0 | `counter_size` | 1 | `u_int8` | The size of the following `clock_value` field in bytes. A typical value would be 4 or 8. |
| 1 | `clock_value` | Variable (`counter_size`) | `u_int` | The raw, free-running counter value. |

#### 3.4.2 Oscillator with Physicals (`clock_source_id = 0x02`)
This payload is for an onboard oscillator and includes essential physical parameters.

*   **Payload Length (N):** 12 bytes

| Offset (Bytes) | Field Name | Size (Bytes) | Data Type | Unit / Scale Factor | Description |
| :---: | :--- | :---: | :--- | :---: | :--- |
| 0 | `clock_value` | 8 | `u_int64` | counts | The raw count of the oscillator. |
| 8 | `temperature` | 2 | `s_int16` | 0.01 °C | Ambient temperature near the oscillator. |
| 10 | `reserved` | 2 | `u_int16` | - | Reserved for future use. |

#### 3.4.3 GNSS-Derived Time with Status (`clock_source_id = 0x03`)
This payload carries precise time derived from a generic GPS/GNSS receiver, along with its operational status.

*   **Payload Length (N):** 16 bytes

| Offset (Bytes) | Field Name | Size (Bytes) | Data Type | Unit / Description |
| :---: | :--- | :---: | :--- | :--- |
| 0 | `gps_week_number` | 2 | `u_int16` | GPS Week Number (weeks since 1980-01-06). |
| 2 | `time_of_week_ms` | 4 | `u_int32` | Time of Week in milliseconds (ms). |
| 6 | `status_flags` | 1 | `u_int8` | A bitfield indicating the synchronization and health status. |
| 7 | `num_sv` | 1 | `u_int8` | Number of space vehicles used in the position fix. |
| 8 | `hdop` | 2 | `u_int16` | Horizontal Dilution of Precision. Scale: 0.01. |
| 10 | `reserved` | 6 | `u_int8` | Reserved for future use. |

#### 3.4.4 JAXA Mission Time (`clock_source_id = 0x10`)
This payload is designed to carry time information formatted according to a common JAXA standard, using a 30-bit seconds counter and a 20-bit microseconds counter relative to a mission-specific Epoch.

*   **Payload Length (N):** 20 bytes

| Offset (Bytes) | Field Name | Size (Bytes) | Data Type | Unit / Description |
| :---: | :--- | :---: | :--- | :--- |
| 0 | `epoch_id` | 1 | `u_int8` | **Epoch Identifier.** See Appendix C. |
| 1 | `reserved_align` | 3 | `u_int8` | Reserved for alignment. |
| 4 | `time_value` | 8 | `u_int64` | **Packed Time Value** (30-bit sec + 20-bit usec). |
| 12 | `bitrate_bps` | 4 | `u_int32` | The nominal bitrate in bps. |
| 16 | `fixed_offset_ns` | 4 | `s_int32` | A fixed, known time offset in nanoseconds. |

**`time_value` Field Structure (64 bits, MSB=0)**

```
  Bit: | 0 ............................. 29 | 30 .................... 49 | 50 .... 63 |
       +------------------------------------+----------------------------+------------+
Value: |       30-bit Seconds Counter       |  20-bit Microseconds Cntr  |  Reserved  |
       +------------------------------------+----------------------------+------------+
```

### 3.5 Checksum Definition

*   **Algorithm:** CRC-16-CCITT-FALSE
    *   **Polynomial:** `0x1021` (`x^16 + x^12 + x^5 + 1`)
    *   **Initial Value:** `0xFFFF`
    *   **Final XOR:** `0x0000`
*   **Calculation Range:** The checksum is calculated over the **TTS Packet only**, from the first byte of the TTS Common Header to the last byte of the Data Payload.

---

## Appendix A: Assigned Clock Source IDs

| ID | Mnemonic | Description |
| :---: | :--- | :--- |
| `0x00` | `NULL` | Null Packet / Reserved |
| `0x01` | `SIMPLE_COUNTER` | A simple, variable-length, free-running counter value. |
| `0x02` | `OSCILLATOR_WITH_PHYSICALS` | An oscillator count with key physical parameters (e.g., temperature). |
| `0x03` | `GNSS_DERIVED_TIME` | GNSS-derived time with operational status. |
| `0x04`-`0x0F` | - | Reserved for future definition. |
| `0x10` | `JAXA_MISSION_TIME` | JAXA standard time format (30-bit sec + 20-bit usec). |
| `0x11`-`0xFE` | - | Reserved for future definition. |
| `0xFF` | `TEST` | For testing purposes. |

## Appendix B: Assigned Coding Scheme IDs

| ID | Mnemonic | Description |
| :---: | :--- | :--- |
| `0x00` | `UNDEFINED` | Undefined or Not Applicable |
| `0x01` | `RS_CONV` | Reedsolomon + Convolutional Code |
| `0x02` | `TURBO` | Turbo Code |
| `0x03` | `LDPC` | LDPC Code |

## Appendix C: Assigned Epoch IDs

| ID | Mnemonic | Epoch Datetime (UTC) |
| :---: | :--- | :--- |
| `0x00` | `UNDEFINED` | Undefined |
| `0x01` | `GPS_EPOCH` | 1980-01-06 00:00:00 |
| `0x02` | `USER_DEFINED_EPOCH_1` | Mission Specific. The exact datetime is defined by the ground system's configuration. |
| `0x03` | `USER_DEFINED_EPOCH_2` | Mission Specific. The exact datetime is defined by the ground system's configuration. |
| `0x04`-`0xFF` | - | Reserved for future definition, including more user-defined epochs. |

## Appendix D: Assigned TLV Type IDs for TCEH

This appendix defines standard types for the TLV fields within the TCDU Context Extension Header (TCEH).

| Type ID | Mnemonic | Length (L) | Value (V) Description |
| :---: | :--- | :---: | :--- |
| `0x01` | `BITRATE_BPS` | 4 | `u_int32`, nominal bitrate in bits per second. |
| `0x02` | `ANTENNA_ID` | 1 | `u_int8`, bitfield identifying the active antenna system. e.g., Bit 0: A(0)/B(1), Bit 1: HGA(0)/LGA(1). |
| `0x03` | `TX_PATH_ID` | 1 | `u_int8`, an ID for the specific transmitter-to-antenna signal path. |
| `0x04` | `GLOBAL_OFFSET_NS` | 4 | `s_int32`, a global, fixed time offset in nanoseconds. |
| `0x05` | `CODING_SCHEME_ID` | 1 | `u_int8`, an ID for the coding scheme. See Appendix B. |
| `0x06`-`0x7F` | - | - | Reserved for future standard definition. |
| `0x80`-`0xFF` | - | - | Reserved for mission-specific, user-defined parameters. |

## Appendix E: Data Structure

1. TCDU Structure
```
+--------------------------------+--------------------------------+--------------------------------+
|       TCDU Header              | [Optional] TCDU Context Ext.   |          TTS Packet            |
|       (8 bytes, Fixed)         |    Header (TCEH)               |      (P bytes, Variable)       |
|                                |   (M bytes, Variable)          |                                |
+--------------------------------+--------------------------------+--------------------------------+
```

2. TCDU Header
```
Byte Offset
 0          1          2          3          4          5          6          7
+-------------------------------------------------------------------------------+
|         SCID (16)    | VCID (8) |TCEHLen(8)|          Reserved (32)           |
+-------------------------------------------------------------------------------+
```

3. TCDU Context Extension
```
<-- TLV 1 --> <-- TLV 2 --> <--- ...
+----------+----------+----------------+----------+----------+----------------+----
| Type (8) | Len=L1(8)| Value (L1 * 8) | Type (8) | Len=L2(8)| Value (L2 * 8) | ...
+----------+----------+----------------+----------+----------+----------------+----
```

Sample including Bitrate and Antenna
```
+----------+----------+--------------------------------+----------+----------+----------+
| Type=0x01| Len=4(8) |    Bitrate BPS (32)            | Type=0x02| Len=1(8) |AntennaID |
+----------+----------+--------------------------------+----------+----------+----------+
```

4. TTS Packet

```
+---------------------------------+--------------------------------+----------------------------+--------------+
|       TTS Common Header         | [Optional] Timestamp Ext. Hdr  |       Data Payload         |   Checksum   |
|      (12 bytes, Fixed)          |      (4 bytes, if present)     |    (N bytes, Variable)     |   (2 bytes)  |
+---------------------------------+--------------------------------+----------------------------+--------------+
```

```
Byte Offset
 0          1          2          3          4          5          6          7
+----------+----------+------------------+----------------------------------------+
|Ver|T|Rsvd| ClockSrc |  Packet Length   |           VC Frame Counter (32)        |
| (4)(1)(3)|   ID (8) |      (16)        |                                        |
+----------+----------+------------------+----------------------------------------+

 8          9         10         11
+----------------------------------------+
|         Timestamp Seconds (32)         |
+----------------------------------------+
```

If TEH flag is 1:
```
+----------------------------------------+
|        Subsecond Fraction (32)         |
+----------------------------------------+
```

5. Clock Value

- Sample 1) clock_source_id = 0x01 (Simple Counter, 64-bit)
    - Payload Length (N) = 9 bytes

```
+------------+-------------------------------------------------------------------+
| Size=8 (8) |                      Clock Value (64)                             |
+------------+-------------------------------------------------------------------+
```

- Sample 2) clock_source_id = 0x02 (Oscillator with Physicals)
    - Payload Length (N) = 12 bytes

```
+-------------------------------------------------------------------+------------------+--------------+
|                          Clock Value (64)                         |  Temperature(16) | Reserved(16) |
+-------------------------------------------------------------------+------------------+--------------+
```