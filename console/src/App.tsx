import { Navigate, Route, Routes } from "react-router-dom";
import { Shell } from "@/components/layout/Shell";
import { SettingsProvider } from "@/lib/settings";
import { Dashboard } from "@/pages/Dashboard";
import { Alerts } from "@/pages/Alerts";
import { AlertDetail } from "@/pages/AlertDetail";
import { Simulator } from "@/pages/Simulator";
import { Federated } from "@/pages/Federated";
import { LLM as Llm } from "@/pages/LLM";
import { Traffic } from "@/pages/Traffic";
import { Services } from "@/pages/Services";
import { Settings } from "@/pages/Settings";
import { Help } from "@/pages/Help";
import { ComplianceHub } from "@/pages/ComplianceHub";
import { Audit } from "@/pages/Audit";
import { Cases } from "@/pages/Cases";
import { CaseDetail } from "@/pages/CaseDetail";
import { Hunts } from "@/pages/Hunts";
import { Guardrails } from "@/pages/Guardrails";
import { Timeline } from "@/pages/Timeline";
import { AuthCallback } from "@/pages/AuthCallback";
import { Training } from "@/pages/Training";

export default function App() {
  return (
    <SettingsProvider>
      <Shell>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/alerts/:decisionCardId" element={<AlertDetail />} />
          <Route path="/simulator" element={<Simulator />} />
          <Route path="/federated" element={<Federated />} />
          <Route path="/llm" element={<Llm />} />
          <Route path="/traffic" element={<Traffic />} />
          <Route path="/services" element={<Services />} />
          <Route path="/compliance" element={<ComplianceHub />} />
          <Route path="/audit" element={<Audit />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/cases/:caseId" element={<CaseDetail />} />
          <Route path="/hunts" element={<Hunts />} />
          <Route path="/guardrails" element={<Guardrails />} />
          <Route path="/timeline" element={<Timeline />} />
          <Route path="/training" element={<Training />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/help" element={<Help />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Shell>
    </SettingsProvider>
  );
}
