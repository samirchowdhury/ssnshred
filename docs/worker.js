"use strict";

import * as mupdf from "https://cdn.jsdelivr.net/npm/mupdf@1.27.0/dist/mupdf.js";

// ── Helpers ────────────────────────────────────────────────────────────────

const AUTO_SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;

function digitsOnly(s) {
  return s.replace(/\D/g, "");
}

function ssnVariants(raw) {
  const d = digitsOnly(raw);
  if (d.length !== 9) return [raw];
  return [
    d.slice(0, 3) + "-" + d.slice(3, 5) + "-" + d.slice(5),  // 123-45-6789
    d.slice(0, 3) + " " + d.slice(3, 5) + " " + d.slice(5),  // 123 45 6789
    d,                                                          // 123456789
  ];
}

function buildSearchTerms(numbers) {
  const seen = new Set();
  const terms = [];
  for (const n of numbers) {
    for (const v of ssnVariants(n)) {
      if (!seen.has(v)) {
        seen.add(v);
        terms.push(v);
      }
    }
  }
  return terms;
}

function replaceAll(text, terms) {
  let count = 0;
  for (const term of terms) {
    let idx = text.indexOf(term);
    while (idx !== -1) {
      count++;
      text = text.slice(0, idx) + "REDACTED" + text.slice(idx + term.length);
      idx = text.indexOf(term, idx + "REDACTED".length);
    }
  }
  return { text, count };
}

function replaceAutoSSN(text, existingTerms) {
  let count = 0;
  text = text.replace(AUTO_SSN_RE, function (match) {
    if (existingTerms.has(match)) return match;
    count++;
    return "REDACTED";
  });
  return { text, count };
}

/** Convert an array of Quads into a bounding Rect [x0, y0, x1, y1]. */
function quadsToBoundingRect(quads) {
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const quad of quads) {
    // quad: [ulx, uly, urx, ury, llx, lly, lrx, lry]
    for (let i = 0; i < 8; i += 2) {
      if (quad[i] < x0) x0 = quad[i];
      if (quad[i] > x1) x1 = quad[i];
    }
    for (let i = 1; i < 8; i += 2) {
      if (quad[i] < y0) y0 = quad[i];
      if (quad[i] > y1) y1 = quad[i];
    }
  }
  return [x0, y0, x1, y1];
}

function progress(msg) {
  postMessage(["PROGRESS", msg]);
}

// ── Scrub steps ────────────────────────────────────────────────────────────

function scrubPageContent(doc, terms, termsSet, auto) {
  let total = 0;
  const n = doc.countPages();
  for (let i = 0; i < n; i++) {
    progress("Scrubbing page " + (i + 1) + " of " + n + "...");
    const page = doc.loadPage(i);
    let pageHits = 0;

    // Explicit terms
    for (const term of terms) {
      const hits = page.search(term);
      for (const hit of hits) {
        const rect = quadsToBoundingRect(hit);
        const annot = page.createAnnotation("Redact");
        annot.setRect(rect);
        annot.setColor([1, 1, 1]); // white fill
        pageHits++;
      }
    }

    // Auto-detect
    if (auto) {
      const stext = page.toStructuredText("preserve-whitespace");
      const pageText = stext.asText();
      let match;
      const autoRe = /\b\d{3}-\d{2}-\d{4}\b/g;
      while ((match = autoRe.exec(pageText)) !== null) {
        if (termsSet.has(match[0])) continue;
        const hits = page.search(match[0]);
        for (const hit of hits) {
          const rect = quadsToBoundingRect(hit);
          const annot = page.createAnnotation("Redact");
          annot.setRect(rect);
          annot.setColor([1, 1, 1]); // white fill
          pageHits++;
        }
      }
    }

    if (pageHits > 0) {
      page.applyRedactions(false, mupdf.PDFPage.REDACT_IMAGE_PIXELS);
    }
    total += pageHits;
  }
  return total;
}

function scrubMetadata(doc, terms, termsSet, auto) {
  let total = 0;
  const trailer = doc.getTrailer();
  const info = trailer.get("Info");
  if (!info || info.isNull()) return 0;

  const keys = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer"];
  for (const key of keys) {
    const obj = info.get(key);
    if (!obj || obj.isNull()) continue;
    let val;
    try { val = obj.asString(); } catch (e) { continue; }
    if (!val) continue;

    let result = replaceAll(val, terms);
    let newVal = result.text;
    total += result.count;

    if (auto) {
      const autoResult = replaceAutoSSN(newVal, termsSet);
      newVal = autoResult.text;
      total += autoResult.count;
    }

    if (result.count > 0 || (auto && newVal !== val)) {
      info.put(key, doc.newString(newVal));
    }
  }

  // XMP metadata stream (in Catalog)
  const catalog = trailer.get("Root");
  if (catalog) {
    const metaObj = catalog.get("Metadata");
    if (metaObj && !metaObj.isNull()) {
      try {
        const buf = metaObj.readStream();
        let xmp = buf.asString();
        const result = replaceAll(xmp, terms);
        let newXmp = result.text;
        total += result.count;

        if (auto) {
          const autoResult = replaceAutoSSN(newXmp, termsSet);
          newXmp = autoResult.text;
          total += autoResult.count;
        }

        if (newXmp !== xmp) {
          // Replace the stream content
          metaObj.writeStream(newXmp);
        }
      } catch (e) {
        // XMP read/write not supported in all builds — skip
      }
    }
  }

  return total;
}

function scrubFormFields(doc, terms, termsSet, auto) {
  let total = 0;
  const n = doc.countPages();
  for (let i = 0; i < n; i++) {
    const page = doc.loadPage(i);
    let widgets;
    try { widgets = page.getWidgets(); } catch (e) { continue; }

    for (const widget of widgets) {
      let val;
      try { val = widget.getValue(); } catch (e) { continue; }
      if (!val) continue;

      const result = replaceAll(val, terms);
      let newVal = result.text;
      total += result.count;

      if (auto) {
        const autoResult = replaceAutoSSN(newVal, termsSet);
        newVal = autoResult.text;
        total += autoResult.count;
      }

      if (newVal !== val) {
        try { widget.setTextValue(newVal); } catch (e) { /* non-text widget */ }
      }
    }
  }
  return total;
}

function scrubEmbeddedFiles(doc, terms, termsSet, auto) {
  let total = 0;
  let embeddedFiles;
  try { embeddedFiles = doc.getEmbeddedFiles(); } catch (e) { return 0; }

  for (const name in embeddedFiles) {
    const fileSpec = embeddedFiles[name];
    let buf;
    try { buf = doc.getEmbeddedFileContents(fileSpec); } catch (e) { continue; }
    if (!buf) continue;

    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(buf.asUint8Array());
    } catch (e) {
      continue; // skip binary files
    }

    const result = replaceAll(text, terms);
    let newText = result.text;
    total += result.count;

    if (auto) {
      const autoResult = replaceAutoSSN(newText, termsSet);
      newText = autoResult.text;
      total += autoResult.count;
    }

    if (newText !== text) {
      let params;
      try { params = doc.getFilespecParams(fileSpec); } catch (e) { continue; }
      try {
        doc.deleteEmbeddedFile(name);
        const newData = new TextEncoder().encode(newText);
        const newSpec = doc.addEmbeddedFile(
          params.filename || name,
          params.mimetype || "text/plain",
          newData,
          params.creationDate || new Date(),
          params.modificationDate || new Date(),
          false
        );
        doc.insertEmbeddedFile(name, newSpec);
      } catch (e) {
        // best-effort
      }
    }
  }
  return total;
}

// ── Main handler ───────────────────────────────────────────────────────────

onmessage = async function (e) {
  const msg = e.data;
  if (msg.action !== "redact") return;

  try {
    const { buffer, numbers, auto } = msg;
    const terms = buildSearchTerms(numbers);
    const termsSet = new Set(terms);

    progress("Opening PDF...");
    const doc = mupdf.Document.openDocument(buffer, "application/pdf");
    let total = 0;

    // 1. Metadata
    progress("Scrubbing metadata...");
    total += scrubMetadata(doc, terms, termsSet, auto);

    // 2. Form fields
    progress("Scrubbing form fields...");
    total += scrubFormFields(doc, terms, termsSet, auto);

    // 3. Embedded files
    progress("Scrubbing embedded files...");
    total += scrubEmbeddedFiles(doc, terms, termsSet, auto);

    // 4. Page content (the main pass)
    total += scrubPageContent(doc, terms, termsSet, auto);

    // 5. Save with garbage collection
    progress("Saving with garbage collection...");
    const outBuf = doc.saveToBuffer("garbage=4,compress=yes");
    const pdfBytes = outBuf.asUint8Array().slice(); // copy before destroy

    doc.destroy();

    postMessage(["RESULT", { count: total, pdf: pdfBytes }], [pdfBytes.buffer]);
  } catch (err) {
    postMessage(["ERROR", err.message || String(err)]);
  }
};

postMessage(["READY", null]);
