The following files are used to test the `../assemble.ts` script.

The following updates are performed over the evolving snapshots

snapshot1.json (time: 2022-02-01 12:00:00)
* issuer1: kid = [7JvktUpf1_9NPwdM-70FJT3YdyTiSe2IvmVxxgDSRb0]
* issuer2: kid = [UOvXbgzZj4zL-lt1uJVS_98NHQrQz48FTdqQyNEdaNE]
* issuer3: kid = [-dznmcx21Vu7QQkxz4u4ki-d7XyuBj2Q7_KBdoBGuLE]
* issuer4: kid = [nQM-36EWDZU5kLoCoeOvshvT2P9JUyc8Do6yWRhNokg]

snapshot2.json (time: 2022-02-02 12:00:00)
* issuer1: kid = [7JvktUpf1_9NPwdM-70FJT3YdyTiSe2IvmVxxgDSRb0]
* issuer2: kid = // deleted
* issuer3: kid = [-dznmcx21Vu7QQkxz4u4ki-d7XyuBj2Q7_KBdoBGuLE, NIYjamR_uv5paKe7T9kn4mueOQFx2WlSaNSZzwIUILA] // new kid
* issuer4: kid = [nQM-36EWDZU5kLoCoeOvshvT2P9JUyc8Do6yWRhNokg]
* issuer5: kid = [e09rUHZUE_9ZfduHpQktUv7sOsk_ayGeVAdiIkmIaAQ] // new

snapshot3.json (time: 2022-02-03 12:00:00)
* issuer1: kid = [7JvktUpf1_9NPwdM-70FJT3YdyTiSe2IvmVxxgDSRb0]
* issuer3: kid = [NIYjamR_uv5paKe7T9kn4mueOQFx2WlSaNSZzwIUILA] // revoked kid
* issuer4: kid = [nQM-36EWDZU5kLoCoeOvshvT2P9JUyc8Do6yWRhNokg, X53dodl3nyr7HRw_6mnk06j7V-aYYZPkk2Bb7jpgUQU] // new kid
* issuer5: kid = [e09rUHZUE_9ZfduHpQktUv7sOsk_ayGeVAdiIkmIaAQ]

Assembled: expected.json (should be the same as actual.json after run)
* issuer1: kid = [7JvktUpf1_9NPwdM-70FJT3YdyTiSe2IvmVxxgDSRb0]
* issuer2: kid = [UOvXbgzZj4zL-lt1uJVS_98NHQrQz48FTdqQyNEdaNE]
* issuer3: kid = [NIYjamR_uv5paKe7T9kn4mueOQFx2WlSaNSZzwIUILA]
* issuer4: kid = [nQM-36EWDZU5kLoCoeOvshvT2P9JUyc8Do6yWRhNokg, X53dodl3nyr7HRw_6mnk06j7V-aYYZPkk2Bb7jpgUQU]
* issuer5: kid = [e09rUHZUE_9ZfduHpQktUv7sOsk_ayGeVAdiIkmIaAQ]

npm run assemble -- -s tests/actual.json -c tests/snapshot1.json -n
npm run assemble -- -s tests/actual.json -c tests/snapshot2.json
npm run assemble -- -s tests/actual.json -c tests/snapshot3.json
