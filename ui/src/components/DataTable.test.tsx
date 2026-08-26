import { render, screen } from "@testing-library/react";
import type { ColumnDef } from "@tanstack/react-table";

import { DataTable } from "./DataTable";

interface Row {
  id: string;
  value: string;
}
const columns: ColumnDef<Row>[] = [
  { accessorKey: "id", header: "ID" },
  { accessorKey: "value", header: "Value" }
];

describe("DataTable", () => {
  it("renders rows when data is provided", () => {
    render(
      <DataTable
        caption="Test table"
        columns={columns}
        data={[{ id: "row-1", value: "hello" }]}
        emptyMessage="Nothing here."
      />
    );
    expect(screen.getByText("hello")).toBeInTheDocument();
    expect(screen.queryByText("Nothing here.")).toBeNull();
  });

  it("renders emptyMessage when data is empty", () => {
    render(
      <DataTable
        caption="Test table"
        columns={columns}
        data={[]}
        emptyMessage="Nothing here."
      />
    );
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });
});
