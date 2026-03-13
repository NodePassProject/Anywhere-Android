package com.argsment.anywhere.ui.components

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.argsment.anywhere.R

private val iconResources = mapOf(
    "Telegram" to R.drawable.ic_brand_telegram,
    "Netflix" to R.drawable.ic_brand_netflix,
    "YouTube" to R.drawable.ic_brand_youtube,
    "Disney+" to R.drawable.ic_brand_disney_plus,
    "TikTok" to R.drawable.ic_brand_tiktok,
    "ChatGPT" to R.drawable.ic_brand_chatgpt,
    "Claude" to R.drawable.ic_brand_claude,
)

private val iconColors = mapOf(
    "Direct" to Color(0xFF4CAF50),
    "Telegram" to Color(0xFF2AABEE),
    "Netflix" to Color(0xFFE50914),
    "YouTube" to Color(0xFFFF0000),
    "Disney+" to Color(0xFF113CCF),
    "TikTok" to Color(0xFF000000),
    "ChatGPT" to Color(0xFF10A37F),
    "Claude" to Color(0xFFD97706),
    "Gemini" to Color(0xFF4285F4),
    "ADBlock" to Color(0xFFF44336),
)

@Composable
fun AppIconView(
    name: String,
    modifier: Modifier = Modifier
) {
    val iconRes = iconResources[name]

    if (iconRes != null) {
        Image(
            painter = painterResource(iconRes),
            contentDescription = name,
            contentScale = ContentScale.Crop,
            modifier = modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
        )
    } else {
        val bgColor = iconColors[name] ?: MaterialTheme.colorScheme.primary
        val initial = name.firstOrNull()?.uppercase() ?: "?"

        Box(
            modifier = modifier
                .size(40.dp)
                .clip(RoundedCornerShape(8.dp))
                .background(bgColor),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = initial,
                color = Color.White,
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold
            )
        }
    }
}
