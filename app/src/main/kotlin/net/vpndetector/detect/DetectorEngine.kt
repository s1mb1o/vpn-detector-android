package net.vpndetector.detect

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import net.vpndetector.detect.consistency.ConsistencyChecks
import net.vpndetector.detect.geoip.GeoIpProbes
import net.vpndetector.detect.probes.ActiveProbes

object DetectorEngine {

    /** Run all categories in parallel and return all checks with a verdict. */
    suspend fun runAll(ctx: Context): Pair<List<Check>, Verdict> = withContext(Dispatchers.IO) {
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
            all to VerdictAggregator.aggregate(all)
        }
    }
}
