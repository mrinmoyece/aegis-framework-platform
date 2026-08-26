export function Status({ value, urgent = false }: { value: string; urgent?: boolean }) {
  return (
    <span className={`status status-${value}`} role={urgent ? "alert" : undefined}>
      <span aria-hidden="true">
        {value.includes("healthy") || value === "passed" ? "●" : "◆"}
      </span>{" "}
      {value.replaceAll("-", " ")}
    </span>
  );
}

export function Timestamp({ value }: { value: string }) {
  const date = new Date(value);
  return (
    <time dateTime={value} title={date.toISOString()}>
      {new Intl.DateTimeFormat(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZoneName: "short"
      }).format(date)}
    </time>
  );
}
