// Loads the detector-stage web model (built by scripts/import-detector-stage.py) and merges the
// interpretation layer. Throws at build time if any captured detector or service is missing content,
// so the page never renders an unexplained finding.
import model from "./captures.json";
import { detectorContent, serviceContent } from "./captures-content";

export interface SiemRecord {
  elasticsearch: { _index: string; _id: string; _source: Record<string, unknown> };
  cef: string;
}
export interface Lifecycle {
  state: string;
  enrichment_state: string;
  devo_delivery_state: string;
  revision: number;
  suppression_reason: string;
}
export interface CaptureDetector {
  detector_id: string;
  category: string;
  severity: number;
  confidence: number;
  mitre: string[];
  why: string;
  fired_count: number;
  variant_whys: string[];
  source_record: Record<string, unknown> | null;
  finding: Record<string, unknown>;
  delivered: boolean;
  lifecycle: Lifecycle;
  siem: SiemRecord | null;
  meaning: string;
  investigation: string[];
}
export interface CaptureService {
  service: string;
  fixture: string;
  captured_at: string;
  title: string;
  blurb: string;
  limit: string;
  suricata: { record_count: number; alerts: number; records: Record<string, unknown>[] };
  detector_count: number;
  finding_count: number;
  delivered_count: number;
  suppressed_count: number;
  detectors: CaptureDetector[];
}

const services: CaptureService[] = model.services.map((s: any) => {
  const sc = serviceContent[s.service];
  if (!sc) throw new Error(`captures: no service content for ${s.service}`);
  return {
    ...s,
    ...sc,
    detectors: s.detectors.map((d: any) => {
      const dc = detectorContent[d.detector_id];
      if (!dc) throw new Error(`captures: no content for detector ${d.detector_id}`);
      return { ...d, ...dc };
    }),
  };
});

export const captureSummary = {
  services: model.total_services,
  detectors: model.total_detectors,
  findings: model.total_findings,
  delivered: model.total_delivered,
  suppressed: model.total_suppressed,
  suricataAlerts: model.total_suricata_alerts,
};
export const captureServices = services;
