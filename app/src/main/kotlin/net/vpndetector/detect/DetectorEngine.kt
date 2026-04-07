package net.vpndetector.detect

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import net.vpndetector.data.model.RunResult
import net.vpndetector.detect.consistency.ConsistencyChecks
import net.vpndetector.detect.geoip.GeoIpProbes
import net.vpndetector.detect.probes.ActiveProbes
import net.vpndetector.detect.probes.LocalListenerProbe
import net.vpndetector.detect.probes.Traceroute
import net.vpndetector.detect.system.SystemChecks

object DetectorEngine {

    /** Run all categories in parallel and return a single [RunResult].
     *  [previousRun] is the most recent prior run, used by the history-anomaly check. */
    suspend fun runAll(
        ctx: Context,
        tag: String = "",
        previousRun: RunResult? = null,
    ): RunResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val systemDef = async { SystemChecks.run(ctx) }
            val probesDef = async { GeoIpProbes.runAll() }
            val activeDef = async { ActiveProbes.run() }
            val tracerouteDef = async { Traceroute.run(ctx) }
            val listenerDef = async { LocalListenerProbe.run() }

            val system = systemDef.await()
            val probes = probesDef.await()
            val geoip = GeoIpProbes.derive(probes)
            val consistency = ConsistencyChecks.run(ctx, probes)
            val active = activeDef.await()
            val traceroute = tracerouteDef.await()
            val listener = listenerDef.await()
            val history = HistoryChecks.run(geoip, previousRun)

            val all = system + geoip + consistency + active + traceroute + listener + history
            val now = System.currentTimeMillis()
            RunResult(
                timestamp = now,
                tag = tag,
                checks = all,
                verdict = VerdictAggregator.aggregate(all),
            )
        }
    }
}
