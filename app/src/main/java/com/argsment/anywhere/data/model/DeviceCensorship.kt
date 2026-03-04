package com.argsment.anywhere.data.model

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Rect

object DeviceCensorship {
    /**
     * Detects if the device censors certain flag emojis (e.g. China devices).
     *
     * Renders the Taiwan flag emoji and checks if the output is monochrome
     * (grayscale = censored) vs colorful (normal rendering).
     */
    fun isChinaDevice(): Boolean {
        val bannedCharacter = "\uD83C\uDDF9\uD83C\uDDFC" // 🇹🇼

        val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
            textSize = 24f
        }

        val bounds = Rect()
        paint.getTextBounds(bannedCharacter, 0, bannedCharacter.length, bounds)
        val width = bounds.width().coerceAtLeast(1)
        val height = bounds.height().coerceAtLeast(1)

        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        canvas.drawText(bannedCharacter, -bounds.left.toFloat(), -bounds.top.toFloat(), paint)

        for (x in 0 until bitmap.width) {
            for (y in 0 until bitmap.height) {
                val pixel = bitmap.getPixel(x, y)
                val r = (pixel shr 16) and 0xFF
                val g = (pixel shr 8) and 0xFF
                val b = pixel and 0xFF
                if (!(r == g && g == b)) {
                    bitmap.recycle()
                    return false
                }
            }
        }

        bitmap.recycle()
        return true
    }
}
