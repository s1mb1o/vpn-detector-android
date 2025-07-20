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

object DetectorEngine {

    suspend fun runAll(ctx: Context, tag: String = ""): RunResult = withContext(Dispatchers.IO) {
        coroutineScope {
            val systemDef = async { SystemChecks.run(ctx) }
            val probesDef = async { GeoIpProbes.runAll() }
            val activeDef = async { ActiveProbes.run() }

            val system = systemDef.await()
            val probes = probesDef.await()
            val geoip = GeoIpProbes.derive(probes)
            val consistency = ConsistencyChecks.run(ctx, probes)
            val active = activeDef.await()

            val all = system + geoip + consistency + active
            RunResult(
                timestamp = System.currentTimeMillis(),
                tag = tag,
                checks = all,
                verdict = VerdictAggregator.aggregate(all),
            )
        }
    }
}
