const PORT = 3000;
const BASE_URL = `http://localhost:${PORT}`;

async function runDemo() {
  console.log("==========================================================");
  console.log("       STARTING MUUNGANO V2 MULTI-LEDGER ZK-ILP DEMO      ");
  console.log("==========================================================\n");

  // ------------------------------------------------------------
  // SCENARIO 1: SUCCESS CASE (User scores 400 + 350 = 750 >= 700 threshold)
  // ------------------------------------------------------------
  console.log("--- SCENARIO 1: Successful Compliance (Aggregate Score 750 >= 700) ---");
  
  // Step 1: Quote Phase
  console.log("[Lender Side]: Requesting Quote for credit line of $150...");
  const quoteRes = await fetch(`${BASE_URL}/quotes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: 150, borrowerId: 'borrower-750' })
  });
  
  const quote = await quoteRes.json();
  const challenge = quoteRes.headers.get('x-muungano-challenge');
  console.log(`[Quote Received]: URL=${quote.id}`);
  console.log(`[Quote parameters]: Required Score Threshold=${quote.customRiskThreshold}`);
  console.log(`[Challenge/Lock Condition (H)]: ${quote.executionCondition}\n`);

  // Step 2: Proving Phase
  console.log("[Client Side]: Intercepting challenge & compiling multi-ledger Halo2 proof locally...");
  console.log("[Client Side]: Mobile Money score = 400, Bank score = 350. (Aggregate = 750)");
  
  const proofRes = await fetch(`${BASE_URL}/client/generate-proof`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ quoteId: challenge, score_1: 400, score_2: 350 })
  });

  const proofData = await proofRes.json();
  if (!proofData.success) {
    console.error("Proving failed:", proofData.error);
    return;
  }
  console.log(`[Proof Generated]: Succinct proof successfully compiled.`);
  console.log(`[Proof Public Inputs]: Root 1 = ${proofData.proof.public_inputs.public_root_1.substring(0, 16)}...`);
  console.log(`[Proof Public Inputs]: Root 2 = ${proofData.proof.public_inputs.public_root_2.substring(0, 16)}...`);
  console.log(`[Proof Public Inputs]: Threshold = ${proofData.proof.public_inputs.public_threshold}`);
  console.log(`[Proof Public Inputs]: HashLock H = ${proofData.proof.public_inputs.public_quote_id}\n`);

  // Step 3 & 4: ILP Prepare and Gateway Connector Verification
  console.log("[ILP Transport]: Packaging ZK proof into the prepare packet custom headers...");
  console.log("[ILP Connector]: Intercepting ILP Prepare packet and running verification key...");
  
  const ilpRes = await fetch(`${BASE_URL}/ilp/prepare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      amount: "150",
      destination: "peer.lender",
      executionCondition: proofData.executionCondition,
      customHeaders: {
        "X-Muungano-Proof": proofData.proof
      }
    })
  });

  const ilpResult = await ilpRes.json();
  console.log(`[ILP Router Action]: Status=${ilpResult.status}`);
  console.log(`[ILP Router Message]: ${ilpResult.receipt}\n`);

  // ------------------------------------------------------------
  // SCENARIO 2: FAILURE CASE (User scores 300 + 350 = 650 < 700 threshold)
  // ------------------------------------------------------------
  console.log("--- SCENARIO 2: Compliance Failure (Aggregate Score 650 < 700) ---");

  // Step 1: Quote Phase
  console.log("[Lender Side]: Requesting Quote for credit line of $200...");
  const quoteRes2 = await fetch(`${BASE_URL}/quotes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: 200, borrowerId: 'borrower-650' })
  });
  
  const quote2 = await quoteRes2.json();
  const challenge2 = quoteRes2.headers.get('x-muungano-challenge');
  console.log(`[Quote Received]: URL=${quote2.id}`);
  console.log(`[Quote parameters]: Required Score Threshold=${quote2.customRiskThreshold}`);
  console.log(`[Challenge/Lock Condition (H)]: ${challenge2}\n`);

  // Step 2: Proving Phase (fails)
  console.log("[Client Side]: Mobile Money score = 300, Bank score = 350. (Aggregate = 650)");
  console.log("[Client Side]: Attempting to compile ZK proof (expecting circuit to reject)...");
  
  const proofRes2 = await fetch(`${BASE_URL}/client/generate-proof`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ quoteId: challenge2, score_1: 300, score_2: 350 })
  });

  const proofData2 = await proofRes2.json();
  console.log(`[Prover Outcome]: Success=${proofData2.success}`);
  if (!proofData2.success) {
    console.log(`[Prover Error Message]: ${proofData2.error.split('\n')[0]}\n`);
  }

  // Step 3 & 4: Attempt ILP Prepare with invalid/mock proof (force failure)
  console.log("[ILP Transport]: Client sends invalid/tampered proof payload to gateway...");
  
  // Fabricate a proof payload with score edited to bypass range check (tampering)
  const tamperedProof = {
    status: "success",
    public_inputs: {
      public_root_1: "0x153e85c10555355cf7f5af6c60be8c2c789801281003f9d2f75357bdb85ea95c",
      public_root_2: "0x153e85c10555355cf7f5af6c60be8c2c789801281003f9d2f75357bdb85ea95c",
      public_threshold: "0x00000000000000000000000000000000000000000000000000000000000002bc", // 700
      public_quote_id: "0x00000000000000000000000000000000000000000000000000000000000181cd" // Hardcoded wrong lock
    },
    witness_proof: {
      private_score_1: "0x0000000000000000000000000000000000000000000000000000000000000190",
      private_salt_1: "0x000000000000000000000000000000000000000000000000000000000000270f",
      private_path_1: ["0x11", "0x22", "0x33", "0x44"],
      private_index_1: "0x05",
      
      private_score_2: "0x000000000000000000000000000000000000000000000000000000000000015e",
      private_salt_2: "0x00000000000000000000000000000000000000000000000000000000000022b8",
      private_path_2: ["0x55", "0x66", "0x77", "0x88"],
      private_index_2: "0x0a",

      private_identity: "0x0000000000000000000000000000000000000000000000000000000000003039"
    }
  };

  const ilpRes2 = await fetch(`${BASE_URL}/ilp/prepare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      amount: "200",
      destination: "peer.lender",
      executionCondition: quote2.executionCondition,
      customHeaders: {
        "X-Muungano-Proof": tamperedProof
      }
    })
  });

  const ilpResult2 = await ilpRes2.json();
  console.log(`[ILP Router Action]: Status=${ilpResult2.status}`);
  console.log(`[ILP Router Message]: ${ilpResult2.reason || ilpResult2.receipt}\n`);

  console.log("==========================================================");
  console.log("         MUUNGANO V2 DEMO CONCLUDED SUCCESSFULLY         ");
  console.log("==========================================================");
}

runDemo();
