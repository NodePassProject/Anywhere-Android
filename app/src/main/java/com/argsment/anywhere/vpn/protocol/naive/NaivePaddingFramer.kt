package com.argsment.anywhere.vpn.protocol.naive

import java.io.ByteArrayOutputStream

/**
 * Encodes and decodes NaiveProxy padding frames for the first N read/write operations.
 *
 * Wire format per frame:
 * ```
 * [1 byte] payload_size >> 8
 * [1 byte] payload_size & 0xFF
 * [1 byte] padding_size
 * [payload_size bytes] payload
 * [padding_size bytes] zeros
 * ```
 *
 * After [maxFrames] frames have been processed, data passes through unframed.
 */
class NaivePaddingFramer(private val maxFrames: Int = 8) {

    companion object {
        const val FRAME_HEADER_SIZE = 3
        const val MAX_PADDING_SIZE = 255
    }

    var numReadFrames = 0
        private set
    var numWrittenFrames = 0
        private set

    // Read state machine
    private enum class ReadState {
        PAYLOAD_LENGTH_1,
        PAYLOAD_LENGTH_2,
        PADDING_LENGTH,
        PAYLOAD,
        PADDING
    }

    private var state = ReadState.PAYLOAD_LENGTH_1
    private var readPayloadLength = 0
    private var readPaddingLength = 0

    /** Whether padding is still active for reads. */
    val isReadPaddingActive: Boolean get() = numReadFrames < maxFrames

    /** Whether padding is still active for writes. */
    val isWritePaddingActive: Boolean get() = numWrittenFrames < maxFrames

    // -- Read --

    /**
     * Reads padded input and extracts payload bytes.
     *
     * Handles partial reads — the framer's state machine resumes across calls.
     * Returns the number of payload bytes written to [output].
     * A return value of 0 means only padding/header bytes were consumed (not EOF).
     */
    fun read(padded: ByteArray, into: ByteArrayOutputStream): Int {
        var offset = 0
        val startCount = into.size()

        while (offset < padded.size) {
            when (state) {
                ReadState.PAYLOAD_LENGTH_1 -> {
                    if (numReadFrames >= maxFrames) {
                        // Past padding threshold — raw passthrough
                        into.write(padded, offset, padded.size - offset)
                        offset = padded.size
                        continue
                    }
                    readPayloadLength = padded[offset].toInt() and 0xFF
                    offset++
                    state = ReadState.PAYLOAD_LENGTH_2
                }

                ReadState.PAYLOAD_LENGTH_2 -> {
                    readPayloadLength = readPayloadLength * 256 + (padded[offset].toInt() and 0xFF)
                    offset++
                    state = ReadState.PADDING_LENGTH
                }

                ReadState.PADDING_LENGTH -> {
                    readPaddingLength = padded[offset].toInt() and 0xFF
                    offset++
                    state = ReadState.PAYLOAD
                }

                ReadState.PAYLOAD -> {
                    val available = padded.size - offset
                    val copySize = minOf(readPayloadLength, available)
                    readPayloadLength -= copySize
                    into.write(padded, offset, copySize)
                    offset += copySize
                    if (readPayloadLength == 0) {
                        state = ReadState.PADDING
                    }
                }

                ReadState.PADDING -> {
                    val available = padded.size - offset
                    val skipSize = minOf(readPaddingLength, available)
                    readPaddingLength -= skipSize
                    offset += skipSize
                    if (readPaddingLength == 0) {
                        if (numReadFrames < Int.MAX_VALUE - 1) {
                            numReadFrames++
                        }
                        state = ReadState.PAYLOAD_LENGTH_1
                    }
                }
            }
        }

        return into.size() - startCount
    }

    // -- Write --

    /**
     * Wraps [payload] in a padding frame with the given padding size.
     *
     * Returns the framed data (header + payload + zero-padding).
     */
    fun write(payload: ByteArray, paddingSize: Int): ByteArray {
        val actualPadding = minOf(paddingSize, MAX_PADDING_SIZE)
        val frameSize = FRAME_HEADER_SIZE + payload.size + actualPadding

        val frame = ByteArray(frameSize)
        frame[0] = (payload.size / 256).toByte()
        frame[1] = (payload.size % 256).toByte()
        frame[2] = actualPadding.toByte()
        System.arraycopy(payload, 0, frame, FRAME_HEADER_SIZE, payload.size)
        // Remaining bytes are already zero (padding)

        if (numWrittenFrames < Int.MAX_VALUE - 1) {
            numWrittenFrames++
        }

        return frame
    }
}
