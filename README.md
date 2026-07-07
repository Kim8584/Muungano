# Muungano V2: Decentralized ZK-Information Signaling over Interledger and Open Payments

[**Muungano**](https://github.com/Kim8584/Muungano/blob/main/paper/main.pdf) (Swahili for *Union/Connection*) is a decentralized, privacy-preserving financial reputation and trust infrastructure built natively on the Interledger Protocol (ILP) and Open Payments architecture. 

It enables underserved individuals and MSMEs across emerging markets to prove their creditworthiness across fragmented, siloed transactional ledgers (e.g., Mobile Money and Bank logs) using a single, succinct Zero-Knowledge proof compiled locally on their phone. Lenders and gateways gain absolute mathematical certainty of creditworthiness without ever seeing or storing the borrower's raw transaction records, completely eliminating centralized data honeypots.

---

## 📄 The White Paper

<p align="center">
  <a href="https://github.com/Kim8584/Muungano/blob/main/paper/main.pdf">
    <img src="https://img.shields.io/badge/The%20White%20Paper-PDF%20Viewer-blue?style=for-the-badge&logo=read-the-docs&logoColor=white" alt="The White Paper" />
  </a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://github.com/Kim8584/Muungano/raw/main/paper/main.pdf">
    <img src="https://img.shields.io/badge/Download%20Paper-Direct%20Download-green?style=for-the-badge&logo=gitbook&logoColor=white" alt="Download Paper" />
  </a>
</p>

---

## 🛠️ The Architecture

```
                                  [ OUT-OF-BAND SIGNALING ]
                                  
   1. Request Quote
  Lender ─────────────────────────── GET /quotes ──────────────────────────► Client Wallet
                                                                                  │
   2. Challenge (Quote ID & HTLC Lock H)                                          │
  Lender ◄─────────────────────── X-Muungano-Challenge ───────────────────────────┘
                                                                                  │
   3. Local Proving (Phone)                                                       ▼
  Mobile Money API ─────────► [ SMT Root 1 ] ──┐                                [ Local ]
  Bank Ledger API ──────────► [ SMT Root 2 ] ──┼──► generates proof (π) ──► [ ZK-HTLC Circuit ]
  Identity Witness ─────────► [ W_identity ] ──┘                                [ PLONKish ]
                                                                                  │
   4. Submit Proof via GNAP                                                       │
  Gateway Node ◄───────────────── POST /ilp/prepare (custom headers) ──────────────┘
       │
       ▼ (Halo2 Verification)
  [ Verified? ] ─── YES ───► Route STREAM Packets ───► Lender reveals Preimage (S) ──► Fulfill
```

---

## ✨ Key Features

1. **Client-Side Mobile Proving (Absolute Privacy):** Proof generation occurs entirely locally on the user's mobile device. Raw records, identity keys, and ledger transactions never leave the phone. Lenders and gateways only interact with the final succinct proof string.
2. **Multi-Ledger State Aggregation:** The circuit performs double Poseidon Merkle membership proof climbs concurrently to verify membership in two independent registries (e.g., Mobile Money and Banking) sharing the same `W_identity` witness, verifying:
   $$S_{\text{total}} = S_{\text{mobile money}} + S_{\text{bank}} \ge T_{\text{threshold}}$$
3. **ZK-HTLC Replay Protection:** Binds the ZK proof directly to the lender's HTLC SHA256 lock condition ($H = \text{SHA256}(S)$) as a public input. This makes the proof single-use, preventing malicious nodes from intercepting and replaying the proof on other payment requests.
4. **Out-of-Band GNAP Handshake:** Standard ILP STREAM transport enforces a 1500-byte MTU limit. Since ZK proofs exceed this boundary, Muungano shifts proof signaling out-of-band to the Open Payments API layer during the GNAP authorization phase.

---

## 📂 Project Structure

*   [`circuits/`](file:///home/kimani/Umoroto/muunganoV2/circuits): Halo2-based Zero-Knowledge circuits implemented in Rust.
    *   [`src/lib.rs`](file:///home/kimani/Umoroto/muunganoV2/circuits/src/lib.rs): Contains Poseidon tree-membership chips, aggregate range gates, and circuit tests.
    *   [`src/main.rs`](file:///home/kimani/Umoroto/muunganoV2/circuits/src/main.rs): Command-line wrapper containing `prove`, `verify`, and `generate-mock-tree` commands.
*   [`server/`](file:///home/kimani/Umoroto/muunganoV2/server): Express.js middleware server simulating the ILP routing gateway and borrower client wallet.
    *   [`index.js`](file:///home/kimani/Umoroto/muunganoV2/server/index.js): API endpoints (/quotes, /client/generate-proof, /ilp/prepare).
    *   [`index.html`](file:///home/kimani/Umoroto/muunganoV2/server/index.html): Interactive visual dashboard with sliders, SVG active-path visualizer, and live terminal console.
*   [`paper/`](file:///home/kimani/Umoroto/muunganoV2/paper): Academic whitepaper describing the mathematics, arithmetization matrix, and protocol flows.
    *   [`main.pdf`](file:///home/kimani/Umoroto/muunganoV2/paper/main.pdf): Compiled paper PDF ready for publication.
*   [`resources/`](file:///home/kimani/Umoroto/muunganoV2/resources): Architecture diagrams, SMT trees, and tables.

---

## 🚀 Getting Started

### Prerequisites
*   **Rust (Cargo):** For compiling and running ZK circuits.
*   **Node.js (npm):** For hosting the gateway server and dashboard.

### 1. Compile the ZK Circuits (Release Mode)
Build the high-performance release binary to achieve sub-200ms proving times:
```bash
cd circuits
cargo build --release --bin circuits
```

### 2. Launch the Express Gateway Server
Install dependencies and run the local server daemon:
```bash
cd ../server
npm install
npm start
```
The server will start at **`http://localhost:3000`**. Open this address in your browser to interact with the visual simulator!

### 3. Run the End-to-End Handshake Simulation CLI
To run the automated test suite simulating compliance success and failure flows:
```bash
cd server
npm run demo
```

---

## 👥 Author
*   **Stephen Kimani Njoroge** (sknjorogeus2026@usiu.ac.ke)

*USIU -Africa.*
