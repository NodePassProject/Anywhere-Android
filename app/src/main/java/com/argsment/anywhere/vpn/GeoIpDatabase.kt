package com.argsment.anywhere.vpn

import android.content.Context
import android.util.Log

/**
 * Loads and queries a custom binary GeoIP database for IPv4 country lookups.
 * Used to implement per-country bypass (traffic to IPs in a specific country goes direct).
 *
 * File format:
 *   Offset 0-3:  Magic "GEO1"
 *   Offset 4-7:  Entry count (big-endian uint32)
 *   Offset 8+:   Entries, each 10 bytes: [startIP(4)] [endIP(4)] [countryCode(2)]
 */
class GeoIpDatabase private constructor(private val data: ByteArray) {

    /**
     * Looks up the country for an IPv4 address string.
     * Returns the packed country code (e.g. "CN" → 0x434E), or 0 if not found.
     */
    fun lookup(ipString: String): Int {
        val result = NativeBridge.nativeGeoipLookup(data, ipString)
        if (result.length == 2) {
            return ((result[0].code and 0xFF) shl 8) or (result[1].code and 0xFF)
        }
        return 0
    }

    companion object {
        private const val TAG = "GeoIP"
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
                Log.e(TAG, "[GeoIP] Failed to load $assetName from assets: $e")
                return null
            }

            if (data.size < HEADER_SIZE) {
                Log.e(TAG, "[GeoIP] File too small: ${data.size} bytes")
                return null
            }

            // Verify magic "GEO1"
            if (data[0] != 0x47.toByte() || data[1] != 0x45.toByte() ||
                data[2] != 0x4F.toByte() || data[3] != 0x31.toByte()
            ) {
                Log.e(TAG, "[GeoIP] Invalid magic header")
                return null
            }

            val count = ((data[4].toInt() and 0xFF) shl 24) or
                    ((data[5].toInt() and 0xFF) shl 16) or
                    ((data[6].toInt() and 0xFF) shl 8) or
                    (data[7].toInt() and 0xFF)

            if (data.size < HEADER_SIZE + count * ENTRY_SIZE) {
                Log.e(TAG, "[GeoIP] File truncated: expected ${HEADER_SIZE + count * ENTRY_SIZE} bytes, got ${data.size}")
                return null
            }

            Log.i(TAG, "[GeoIP] Loaded $count entries")
            return GeoIpDatabase(data)
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
