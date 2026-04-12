package com.argsment.anywhere.vpn

import android.content.Context
import com.argsment.anywhere.vpn.util.AnywhereLogger

/**
 * Loads and queries a custom binary GeoIP database for IPv4 country lookups.
 * Used to implement per-country bypass (traffic to IPs in a specific country goes direct).
 *
 * File format:
 *   Offset 0-3:  Magic "GEO1"
 *   Offset 4-7:  Entry count (big-endian uint32)
 *   Offset 8+:   Entries, each 10 bytes: [startIP(4)] [endIP(4)] [countryCode(2)]
 */
class GeoIpDatabase private constructor(
    private val data: ByteArray,
    private val entryCount: Int
) {

    /**
     * Looks up the country for an IPv4 address string.
     * Returns the packed country code (e.g. "CN" → 0x434E), or 0 if not found.
     *
     * Binary search over the sorted [startIP, endIP, countryCode] entries,
     * mirroring iOS/`CGeoIP.c::geoip_lookup`.
     */
    fun lookup(ipString: String): Int {
        val ip = parseIPv4(ipString) ?: return 0

        var lo = 0
        var hi = entryCount - 1
        var best = -1

        while (lo <= hi) {
            val mid = lo + (hi - lo) / 2
            val off = HEADER_SIZE + mid * ENTRY_SIZE
            val startIP = readUInt32(off)
            if (java.lang.Integer.compareUnsigned(startIP, ip) <= 0) {
                best = mid
                lo = mid + 1
            } else {
                hi = mid - 1
            }
        }

        if (best < 0) return 0

        val off = HEADER_SIZE + best * ENTRY_SIZE
        val endIP = readUInt32(off + 4)
        if (java.lang.Integer.compareUnsigned(ip, endIP) > 0) return 0

        val c1 = data[off + 8].toInt() and 0xFF
        val c2 = data[off + 9].toInt() and 0xFF
        return (c1 shl 8) or c2
    }

    private fun readUInt32(offset: Int): Int {
        return ((data[offset].toInt() and 0xFF) shl 24) or
                ((data[offset + 1].toInt() and 0xFF) shl 16) or
                ((data[offset + 2].toInt() and 0xFF) shl 8) or
                (data[offset + 3].toInt() and 0xFF)
    }

    /** Parse "a.b.c.d" to a big-endian host-order Int (unsigned). Returns null on bad input. */
    private fun parseIPv4(s: String): Int? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        var result = 0
        for (p in parts) {
            val v = p.toIntOrNull() ?: return null
            if (v < 0 || v > 255) return null
            result = (result shl 8) or v
        }
        return result
    }

    companion object {
        private val logger = AnywhereLogger("GeoIP")
        private const val HEADER_SIZE = 8
        private const val ENTRY_SIZE = 10  // 4 + 4 + 2

        /**
         * Load GeoIP database from assets.
         * Returns null if the file is missing or invalid.
         */
        fun load(context: Context, assetName: String = "geoip.dat"): GeoIpDatabase? {
            val data: ByteArray
            try {
                data = context.assets.open(assetName).use { it.readBytes() }
            } catch (e: Exception) {
                logger.error("[GeoIP] Failed to load $assetName from assets: $e")
                return null
            }

            if (data.size < HEADER_SIZE) {
                logger.error("[GeoIP] File too small: ${data.size} bytes")
                return null
            }

            // Verify magic "GEO1"
            if (data[0] != 0x47.toByte() || data[1] != 0x45.toByte() ||
                data[2] != 0x4F.toByte() || data[3] != 0x31.toByte()
            ) {
                logger.error("[GeoIP] Invalid magic header")
                return null
            }

            val count = ((data[4].toInt() and 0xFF) shl 24) or
                    ((data[5].toInt() and 0xFF) shl 16) or
                    ((data[6].toInt() and 0xFF) shl 8) or
                    (data[7].toInt() and 0xFF)

            if (data.size < HEADER_SIZE + count * ENTRY_SIZE) {
                logger.error("[GeoIP] File truncated: expected ${HEADER_SIZE + count * ENTRY_SIZE} bytes, got ${data.size}")
                return null
            }

            logger.debug("[GeoIP] Loaded $count entries")
            return GeoIpDatabase(data, count)
        }

        /**
         * Packs a 2-letter country code string into Int: (c1 << 8) | c2.
         * Returns 0 for invalid codes.
         */
        fun packCountryCode(code: String): Int {
            if (code.length != 2) return 0
            val c1 = code[0].code and 0xFF
            val c2 = code[1].code and 0xFF
            return (c1 shl 8) or c2
        }
    }
}
