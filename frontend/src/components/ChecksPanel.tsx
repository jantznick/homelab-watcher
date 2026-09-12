import type { CheckItem } from "../api";

export function ChecksPanel({
  items,
  takenAt,
  configSource,
}: {
  items: CheckItem[];
  takenAt: string | null;
  configSource?: string | null;
}) {
  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Checks</h2>
        <div className="meta">
          {items.length} probes
          {takenAt ? ` · ${new Date(takenAt).toLocaleString()}` : ""}
          {configSource ? ` · ${configSource}` : ""}
        </div>
      </div>
      {!items.length ? (
        <div className="empty">No checks yet — add them in Settings.</div>
      ) : (
        <div className="table-scroll">
          <table className="table watched-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Type</th>
                <th>Result</th>
                <th>Latency</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {items.map((w) => (
                <tr key={w.name}>
                  <td className="name">{w.name}</td>
                  <td className="mono">{w.check_type}</td>
                  <td>
                    <span className={w.ok ? "chip chip-ok" : "chip chip-bad"}>
                      {w.ok ? "up" : "down"}
                    </span>
                  </td>
                  <td className="mono">
                    {w.latency_ms != null ? `${Math.round(w.latency_ms)} ms` : "—"}
                  </td>
                  <td className="mono">{w.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
