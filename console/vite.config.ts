import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Backend hosts. Override via env when running outside docker-compose.
// Inside docker-compose these resolve to service DNS names.
const AUDIT = process.env.AUDIT_URL ?? "http://localhost:8022";
const ORCH = process.env.ORCHESTRATOR_URL ?? "http://localhost:8021";
const SIM = process.env.SIMULATOR_URL ?? "http://localhost:8023";
const COLLECTOR = process.env.COLLECTOR_URL ?? "http://localhost:8001";
const DETECTOR = process.env.DETECTOR_URL ?? "http://localhost:8000";
const POLICY = process.env.POLICY_URL ?? "http://localhost:8020";
const OSINT = process.env.OSINT_URL ?? "http://localhost:8028";
const LLM = process.env.LLM_URL ?? "http://localhost:8024";
const FED = process.env.FEDERATED_URL ?? "http://localhost:8010";
const TRAFFIC = process.env.TRAFFIC_URL ?? "http://localhost:8027";

const rewrite = (prefix: string) => (p: string) => p.replace(new RegExp(`^${prefix}`), "");

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
  server: {
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      "/api/audit":        { target: AUDIT,     changeOrigin: true, rewrite: rewrite("/api/audit") },
      "/api/orchestrator": { target: ORCH,      changeOrigin: true, rewrite: rewrite("/api/orchestrator") },
      "/api/simulator":    { target: SIM,       changeOrigin: true, rewrite: rewrite("/api/simulator") },
      "/api/collector":    { target: COLLECTOR, changeOrigin: true, rewrite: rewrite("/api/collector") },
      "/api/detector":     { target: DETECTOR,  changeOrigin: true, rewrite: rewrite("/api/detector") },
      "/api/policy":       { target: POLICY,    changeOrigin: true, rewrite: rewrite("/api/policy") },
      "/api/osint":        { target: OSINT,     changeOrigin: true, rewrite: rewrite("/api/osint") },
      "/api/llm":          { target: LLM,       changeOrigin: true, rewrite: rewrite("/api/llm") },
      "/api/federated":    { target: FED,       changeOrigin: true, rewrite: rewrite("/api/federated") },
      "/api/traffic":      { target: TRAFFIC,   changeOrigin: true, rewrite: rewrite("/api/traffic") },
    },
  },
});
