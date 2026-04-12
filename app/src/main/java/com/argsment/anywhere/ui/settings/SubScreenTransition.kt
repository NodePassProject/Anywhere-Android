package com.argsment.anywhere.ui.settings

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.runtime.Composable

/**
 * Horizontal push/pop transition used for in-screen drill-down navigation,
 * mirroring the default iOS NavigationStack behaviour.
 *
 * The root destination is always represented by [rootKey]; anything else is
 * treated as a child route.  Going root → child slides the child in from the
 * right; going child → root slides the child back out to the right.
 */
@Composable
internal fun <T> SubScreenHost(
    state: T,
    rootKey: T,
    content: @Composable (T) -> Unit
) {
    AnimatedContent(
        targetState = state,
        transitionSpec = { slideTransition(rootKey) },
        label = "sub-screen"
    ) { current ->
        content(current)
    }
}

private fun <T> AnimatedContentTransitionScope<T>.slideTransition(rootKey: T): ContentTransform {
    val goingBack = targetState == rootKey
    return if (goingBack) {
        slideInHorizontally { -it / 4 } togetherWith slideOutHorizontally { it }
    } else {
        slideInHorizontally { it } togetherWith slideOutHorizontally { -it / 4 }
    }
}
