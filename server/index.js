const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// In-memory store for quotes, preimage/fulfillment states, and transactions
const quotesStore = new Map();
const txStore = new Map();

// Helper to execute the compiled circuits binary
const runCircuitsCli = (args) => {
  return new Promise((resolve, reject) => {
    const binaryPath = path.resolve(__dirname, '../circuits/target/release/circuits');
    const cmd = `"${binaryPath}" ${args.join(' ')}`;
    console.log(`[Executing CLI]: ${cmd}`);
    
    exec(cmd, (error, stdout, stderr) => {
      if (error) {
        console.error(`[CLI Error]:`, stderr || stdout);
        return reject(new Error(stderr || stdout || error.message));
      }
      resolve(stdout.trim());
    });
  });
};

// Helper to extract JSON from stdout containing possible debug prints
const extractJson = (stdout) => {
  const startIndex = stdout.indexOf('{');
  const endIndex = stdout.lastIndexOf('}');
  if (startIndex === -1 || endIndex === -1) {
    throw new Error('Failed to find JSON block in output: ' + stdout);
  }
  return JSON.parse(stdout.substring(startIndex, endIndex + 1));
};

// Helper to convert a string or hex to BN254 Fr field element representation
const hashToFrField = (valueStr) => {
  const hash = crypto.createHash('sha256').update(valueStr).digest();
  // Mask/slice to fit BN254 scalar field limit (~253.9 bits)
  return '0x' + hash.toString('hex').substring(0, 32);
};

// ==========================================
// 1. Open Payments: Quote Phase (HTLC Lock Generation)
// ==========================================
app.post('/quotes', (req, res) => {
  const { amount, borrowerId } = req.body;
  const quoteId = crypto.randomUUID();
  const threshold = 700; 

  // Generate HTLC lock secrets
  const preimage = crypto.randomBytes(32).toString('hex'); // Secret S
  const hashLock = crypto.createHash('sha256').update(preimage).digest('hex'); // Condition H

  const quote = {
    id: `https://lender.wallet/quotes/${quoteId}`,
    assetCode: 'USD',
    assetScale: 2,
    receiveAmount: {
      value: (amount || 150) * 100 + "", // cents
      currency: 'USD'
    },
    customRiskThreshold: threshold,
    borrowerId: borrowerId || 'user-12345',
    // HTLC Fields
    executionCondition: hashLock,
    preimageSimulated: preimage // Saved locally so receiver can reveal it upon validation
  };

  quotesStore.set(quoteId, quote);
  console.log(`[Quote + HTLC Generated]: ID=${quoteId}, Lock(H)=${hashLock}`);

  // Return the challenge (quoteId) in custom header
  res.setHeader('X-Muungano-Challenge', quoteId);
  res.status(201).json(quote);
});

// ==========================================
// 2. Client-Side Simulation: Proving Phase (Binding proof to HTLC Lock)
// ==========================================
app.post('/client/generate-proof', async (req, res) => {
  const { quoteId, score_1, score_2 } = req.body;
  console.log(`[Proving Requested]: QuoteId=${quoteId}, Score1=${score_1}, Score2=${score_2}`);

  const quote = quotesStore.get(quoteId);
  if (!quote) {
    return res.status(404).json({ error: 'Quote not found' });
  }

  try {
    // We bind the ZK proof directly to the HTLC condition (Hash Lock H)
    // representing it as the public input public_quote_id in our circuits
    const hashLockFr = hashToFrField(quote.executionCondition);
    const thresholdFr = quote.customRiskThreshold.toString();
    const score1Fr = score_1.toString();
    const score2Fr = score_2.toString();

    console.log(`[Generating inputs]: Score1=${score1Fr}, Score2=${score2Fr}, Threshold=${thresholdFr}, Challenge/Lock=${hashLockFr}`);

    // Call circuits binary to generate mock Merkle inputs (now takes score1 and score2)
    const treeOut = await runCircuitsCli(['generate-mock-tree', score1Fr, score2Fr, thresholdFr, hashLockFr]);
    const circuitInputs = extractJson(treeOut);

    // Save inputs temporarily
    const tempInputFile = path.join(__dirname, `temp_input_${quoteId}.json`);
    fs.writeFileSync(tempInputFile, JSON.stringify(circuitInputs));

    // Run prove command on circuits CLI to verify and package the proof
    console.log(`[Running ZK Prover in circuits chip]`);
    const proveOut = await runCircuitsCli(['prove', `...filename...`].map(x => x === '...filename...' ? `"${tempInputFile}"` : x));
    const proofPayload = extractJson(proveOut);

    // Cleanup temp file
    fs.unlinkSync(tempInputFile);

    console.log(`[ZK Proof Generated Successfully]`);
    res.json({
      success: true,
      proof: proofPayload,
      executionCondition: quote.executionCondition
    });
  } catch (error) {
    console.error(`[Proving Failure]:`, error.message);
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

// ==========================================
// 3. ILP Lifecycle: Prepare/Verify Route with preimage release
// ==========================================
app.post('/ilp/prepare', async (req, res) => {
  const { amount, destination, customHeaders, executionCondition } = req.body;
  const proofHeader = customHeaders ? customHeaders['X-Muungano-Proof'] : null;

  if (!proofHeader) {
    console.log(`[ILP Reject]: Missing ZK proof header`);
    return res.status(400).json({
      status: 'Reject',
      reason: 'ILP Reject T01: Missing X-Muungano-Proof compliance header'
    });
  }

  try {
    const proofJson = typeof proofHeader === 'string' ? JSON.parse(proofHeader) : proofHeader;
    
    // The public input quote ID is matched against the hash lock H
    const publicQuoteIdInProof = proofJson.public_inputs.public_quote_id;
    const executionConditionFr = hashToFrField(executionCondition);

    // Validate that the proof was generated specifically for this payment condition H
    if (BigInt(publicQuoteIdInProof) !== BigInt(executionConditionFr)) {
      console.log(`[ILP Reject]: Proof is bound to a different hash lock condition`);
      return res.status(400).json({
        status: 'Reject',
        reason: 'ILP Reject T04: Proof Replay detected! Proof is not bound to this payment condition'
      });
    }

    // Save proof to temp file to verify
    const tempProofFile = path.join(__dirname, `temp_proof_${Date.now()}.json`);
    fs.writeFileSync(tempProofFile, JSON.stringify(proofJson));

    // Call verify command
    console.log(`[Verifying ZK proof against public parameters]`);
    const verifyOut = await runCircuitsCli(['verify', `...filename...`].map(x => x === '...filename...' ? `"${tempProofFile}"` : x));
    fs.unlinkSync(tempProofFile);

    const isVerified = verifyOut.includes('true');

    if (isVerified) {
      console.log(`[ILP Gateway]: ZK Proof verified successfully. Forwarding prepare packet...`);

      // Find the preimage matching this hash lock condition (receiver action)
      let matchedPreimage = null;
      let matchedQuoteId = null;

      for (const [qId, q] of quotesStore.entries()) {
        if (q.executionCondition === executionCondition) {
          matchedPreimage = q.preimageSimulated;
          matchedQuoteId = qId;
          break;
        }
      }

      if (!matchedPreimage) {
        console.log(`[ILP Reject]: Receiver cannot find matching preimage for condition`);
        return res.status(400).json({
          status: 'Reject',
          reason: 'ILP Reject T05: No preimage found matching condition'
        });
      }

      // Verify HTLC: hash(preimage) must equal executionCondition
      const computedHash = crypto.createHash('sha256').update(matchedPreimage).digest('hex');
      if (computedHash !== executionCondition) {
        console.log(`[ILP Reject]: HTLC validation error - Preimage mismatch`);
        return res.status(400).json({
          status: 'Reject',
          reason: 'ILP Reject T06: Cryptographic preimage mismatch'
        });
      }

      console.log(`[ILP Fulfill]: Receiver revealed preimage: ${matchedPreimage}. Releasing funds.`);
      
      const transactionId = crypto.randomUUID();
      const tx = {
        transactionId,
        quoteId: matchedQuoteId,
        amount,
        destination,
        timestamp: new Date().toISOString(),
        status: 'Fulfill',
        preimage: matchedPreimage,
        executionCondition
      };
      txStore.set(transactionId, tx);

      res.json({
        status: 'Fulfill',
        fulfillment: matchedPreimage, // The preimage token S which fulfills the payment
        receipt: `ILP Fulfill: Funds released. Preimage [${matchedPreimage.substring(0, 16)}...] verified against Hash Lock [${executionCondition.substring(0, 16)}...].`,
        transaction: tx
      });
    } else {
      console.log(`[ILP Reject]: ZK Proof verification failed`);
      res.status(400).json({
        status: 'Reject',
        reason: 'ILP Reject T02: Invalid Zero-Knowledge Proof. Compliance check failed.'
      });
    }
  } catch (error) {
    console.error(`[ILP Process Error]:`, error.message);
    res.status(400).json({
      status: 'Reject',
      reason: `ILP Reject T03: Verification execution error: ${error.message}`
    });
  }
});

// GET endpoints for stats / logs
app.get('/transactions', (req, res) => {
  res.json(Array.from(txStore.values()));
});

app.get('/quotes', (req, res) => {
  res.json(Array.from(quotesStore.values()));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`Muungano V2 ZK-ILP Gateway running at http://localhost:${PORT}`);
  console.log(`======================================================\n`);
});
