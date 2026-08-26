import { render, screen } from "@testing-library/react";
import type { ColumnDef } from "@tanstack/react-table";
import { DataTable } from "./DataTable";

type Row = { id: string; label: string };
const columns: ColumnDef<Row>[] = [
  { accessorKey: "id", header: "ID" },
  { accessorKey: "label", header: "Label" }
];

it("renders rows when data is provided", () => {
  render(
    <DataTable
      caption="Test table"
      columns={columns}
      data={[{ id: "r1", label: "Row one" }]}
    />
  );
  expect(screen.getByText("Row one")).toBeInTheDocument();
});

it("shows the default empty message when data is empty", () => {
  render(<DataTable caption="Empty table" columns={columns} data={[]} />);
  expect(screen.getByText("No authorized records are available.")).toBeInTheDocument();
});

it("shows a custom empty message when provided", () => {
  render(
    <DataTable
      caption="Empty table"
      columns={columns}
      data={[]}
      emptyMessage="Nothing to display"
    />
  );
  expect(screen.getByText("Nothing to display")).toBeInTheDocument();
});
