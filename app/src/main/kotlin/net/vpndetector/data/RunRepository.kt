package net.vpndetector.data

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.builtins.ListSerializer
import net.vpndetector.data.model.RunResult
import net.vpndetector.net.AppJson

private val Context.dataStore by preferencesDataStore(name = "vpndetector")

class RunRepository(private val ctx: Context) {

    private val key = stringPreferencesKey("history_v1")
    private val maxEntries = 50
    private val serializer = ListSerializer(RunResult.serializer())

    val history: Flow<List<RunResult>> = ctx.dataStore.data.map { prefs ->
        prefs[key]?.let {
            runCatching { AppJson.decodeFromString(serializer, it) }.getOrDefault(emptyList())
        } ?: emptyList()
    }

    suspend fun add(run: RunResult) {
        ctx.dataStore.edit { prefs ->
            val current = prefs[key]?.let {
                runCatching { AppJson.decodeFromString(serializer, it) }.getOrDefault(emptyList())
            } ?: emptyList()
            val updated = (listOf(run) + current).take(maxEntries)
            prefs[key] = AppJson.encodeToString(serializer, updated)
        }
    }

    suspend fun clear() {
        ctx.dataStore.edit { it.remove(key) }
    }

    suspend fun snapshot(): List<RunResult> = history.first()
}
