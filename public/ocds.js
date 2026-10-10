/**
 * BidTrace OCDS 1.1 & RFC 8785 Canonical Hashing Engine (JavaScript / Browser & Node.js)
 * ====================================================================================
 * Guarantees 100% deterministic cross-language parity with bidtrace_py/ocds.py.
 */

(function (global) {
  'use strict';

  /**
   * Sorts keys lexicographically by their UTF-16 code units (RFC 8785 Section 3.2.3).
   * Note: In JavaScript, standard Array.prototype.sort() on strings compares by UTF-16 code units.
   */
  function sortKeysUtf16(keys) {
    return keys.slice().sort();
  }

  /**
   * Canonicalizes arbitrary JavaScript data into a deterministic RFC 8785 (JCS) string.
   */
  function canonicalizeJcs(data) {
    if (data === null) {
      return "null";
    }
    if (typeof data === "boolean") {
      return data ? "true" : "false";
    }
    if (typeof data === "number") {
      if (!isFinite(data)) {
        throw new Error("RFC 8785 does not permit NaN or Infinity");
      }
      if (Object.is(data, -0)) {
        return "0";
      }
      return JSON.stringify(data);
    }
    if (typeof data === "string") {
      return JSON.stringify(data);
    }
    if (Array.isArray(data)) {
      const elements = data.map((item) => canonicalizeJcs(item));
      return "[" + elements.join(",") + "]";
    }
    if (typeof data === "object") {
      const keys = sortKeysUtf16(Object.keys(data));
      const items = keys.map((key) => {
        const k = JSON.stringify(key);
        const v = canonicalizeJcs(data[key]);
        return k + ":" + v;
      });
      return "{" + items.join(",") + "}";
    }
    throw new TypeError("Unsupported data type for RFC 8785 JCS: " + typeof data);
  }

  /**
   * Computes SHA-256 hash of a string, returning hex string.
   * Works in both Browser (crypto.subtle) and Node.js (crypto module).
   */
  async function hashCanonicalJson(data) {
    const canonicalStr = canonicalizeJcs(data);
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(canonicalStr);

    if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
      const hashBuffer = await window.crypto.subtle.digest("SHA-256", dataBytes);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    } else {
      // Node.js environment fallback
      try {
        const nodeCrypto = require("crypto");
        return nodeCrypto.createHash("sha256").update(dataBytes).digest("hex");
      } catch (e) {
        throw new Error("No cryptographic subsystem available for SHA-256 computation.");
      }
    }
  }

  /**
   * Builds an OCDS 1.1 Tender Notice Release.
   */
  async function createTenderNoticeRelease(params) {
    const nowIso = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    const releaseId = `REL-${params.tenderId}-01-TENDER-NOTICE`;

    const release = {
      uri: `https://api.bidtrace.io/ocds/releases/${releaseId}`,
      version: "1.1",
      tag: ["tender"],
      ocid: params.ocid,
      id: releaseId,
      date: nowIso,
      initiationType: "tender",
      parties: [
        {
          id: params.buyerId,
          name: params.buyerName,
          roles: ["buyer", "procuringEntity"]
        }
      ],
      buyer: {
        id: params.buyerId,
        name: params.buyerName
      },
      tender: {
        id: params.tenderId,
        title: params.title,
        description: params.description,
        status: "active",
        procurementMethod: params.authorizedBiddersRoot ? "selective" : "open",
        awardCriteria: params.evaluationType === "QCBS" ? "ratedCriteria" : "lowestCost",
        value: {
          amount: Number(params.estimatedAmount),
          currency: (params.currency || "USD").toUpperCase()
        },
        tenderPeriod: {
          startDate: nowIso,
          endDate: params.submissionDeadlineIso
        },
        submissionMethod: ["electronicSubmission"],
        criteria: [
          {
            id: "CRIT-TECH",
            title: "Technical Evaluation Weight",
            relatesTo: "tenderer",
            weight: params.techWeight || 0.70,
            minimumScore: params.minTechScore || 75.0
          },
          {
            id: "CRIT-FIN",
            title: "Financial Price Evaluation Weight",
            relatesTo: "tenderer",
            weight: params.finWeight || 0.30
          }
        ]
      },
      bidtrace: {
        version: "3.0.0",
        solanaNetwork: "solana-devnet",
        programId: params.solanaProgramId || "x3iSm5BCoXvEfNwT6m6Vs7ApBJtKjvuTm7qKBJtESjZ",
        tenderPda: params.solanaTenderPda || "",
        submissionDeadlineSlot: params.submissionDeadlineSlot || 0,
        evaluationType: params.evaluationType || "QCBS",
        techWeightBps: Math.round((params.techWeight || 0.70) * 10000),
        finWeightBps: Math.round((params.finWeight || 0.30) * 10000),
        minTechScoreBps: Math.round((params.minTechScore || 75.0) * 100),
        bondMode: params.bondMode || "SuretyService",
        bondAmount: Number(params.bondAmount || 0),
        authorizedBiddersRoot: params.authorizedBiddersRoot || "0000000000000000000000000000000000000000000000000000000000000000",
        initTxSignature: params.initTxSignature || "",
        canonicalHash: ""
      }
    };

    // Calculate canonical hash without the canonicalHash field itself
    const payloadCopy = JSON.parse(JSON.stringify(release));
    payloadCopy.bidtrace.canonicalHash = "";
    release.bidtrace.canonicalHash = await hashCanonicalJson(payloadCopy);

    return release;
  }

  // Export module
  const BidTraceOCDS = {
    canonicalizeJcs,
    hashCanonicalJson,
    createTenderNoticeRelease
  };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = BidTraceOCDS;
  } else {
    global.BidTraceOCDS = BidTraceOCDS;
  }
})(typeof window !== "undefined" ? window : global);
