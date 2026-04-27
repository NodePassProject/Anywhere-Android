package com.argsment.anywhere.data.repository

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.io.File
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Writes [text] to [this] atomically: writes to a sibling `.tmp` file then
 * renames it into place via `ATOMIC_MOVE`, so a crash or kill mid-write
 * leaves either the previous file or the new one — never a half-written
 * file that the next launch can't decode.
 *
 * Falls back to `REPLACE_EXISTING` only on filesystems that don't support
 * atomic move (rare, but documented for FUSE-backed paths).
 */
internal fun File.writeTextAtomic(text: String) {
    val tmp = File(parentFile, "$name.tmp")
    tmp.writeText(text)
    try {
        Files.move(
            tmp.toPath(),
            toPath(),
            StandardCopyOption.ATOMIC_MOVE,
            StandardCopyOption.REPLACE_EXISTING
        )
    } catch (_: AtomicMoveNotSupportedException) {
        Files.move(tmp.toPath(), toPath(), StandardCopyOption.REPLACE_EXISTING)
    }
}

/**
 * Shared single-supervised IO scope for repository disk writes. Mirrors iOS
 * `Task.detached` — the caller publishes its in-memory state immediately and
 * the disk fsync happens asynchronously off the calling thread.
 */
internal val repositoryWriterScope: CoroutineScope =
    CoroutineScope(SupervisorJob() + Dispatchers.IO)

/** Schedules an async write. Errors are swallowed and printed; the in-memory state is the source of truth. */
internal fun File.writeTextAsync(text: String, onError: ((Throwable) -> Unit)? = null) {
    repositoryWriterScope.launch {
        try {
            writeTextAtomic(text)
        } catch (e: Throwable) {
            onError?.invoke(e) ?: println("Atomic write failed for ${this@writeTextAsync.name}: $e")
        }
    }
}
