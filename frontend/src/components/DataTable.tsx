import type { ReactNode } from 'react';
import {
  ActionIcon,
  Checkbox,
  Group,
  Pagination,
  Paper,
  Table,
  Text,
  Tooltip,
} from '@mantine/core';
import { IconArrowsSort, IconChevronDown, IconChevronUp } from '@tabler/icons-react';
import {
  flexRender,
  getCoreRowModel,
  type ColumnDef,
  type RowSelectionState,
  type SortingState,
  useReactTable,
} from '@tanstack/react-table';
import { EmptyState } from './AsyncState';

interface DataTableProps<T extends { id?: string }> {
  data: T[];
  columns: ColumnDef<T>[];
  total?: number;
  page?: number;
  pageSize?: number;
  onPageChange?: (page: number) => void;
  sorting?: SortingState;
  onSortingChange?: (sorting: SortingState) => void;
  selectable?: boolean;
  rowSelection?: RowSelectionState;
  onRowSelectionChange?: (selection: RowSelectionState) => void;
  emptyTitle?: string;
  emptyMessage?: string;
  toolbar?: ReactNode;
}

export function DataTable<T extends { id?: string }>({
  data,
  columns,
  total = data.length,
  page = 1,
  pageSize = 20,
  onPageChange,
  sorting = [],
  onSortingChange,
  selectable = false,
  rowSelection = {},
  onRowSelectionChange,
  emptyTitle = 'No records found',
  emptyMessage = 'Adjust the current filters or add data to this workspace.',
  toolbar,
}: DataTableProps<T>) {
  const selectionColumn: ColumnDef<T> = {
    id: 'select',
    header: ({ table }) => (
      <Checkbox
        aria-label="Select all rows on this page"
        checked={table.getIsAllPageRowsSelected()}
        indeterminate={table.getIsSomePageRowsSelected()}
        onChange={table.getToggleAllPageRowsSelectedHandler()}
      />
    ),
    cell: ({ row }) => (
      <Checkbox
        aria-label={`Select row ${row.id}`}
        checked={row.getIsSelected()}
        onChange={row.getToggleSelectedHandler()}
      />
    ),
    enableSorting: false,
    size: 44,
  };

  const table = useReactTable({
    data,
    columns: selectable ? [selectionColumn, ...columns] : columns,
    state: { sorting, rowSelection },
    getRowId: (row, index) => row.id ?? String(index),
    enableRowSelection: selectable,
    manualSorting: true,
    onSortingChange: (updater) => {
      const next = typeof updater === 'function' ? updater(sorting) : updater;
      onSortingChange?.(next);
    },
    onRowSelectionChange: (updater) => {
      const next = typeof updater === 'function' ? updater(rowSelection) : updater;
      onRowSelectionChange?.(next);
    },
    getCoreRowModel: getCoreRowModel(),
  });

  const pageCount = Math.max(1, Math.ceil(total / Math.max(pageSize, 1)));

  return (
    <Paper className="vb-card" radius="md">
      {toolbar ? <div style={{ padding: 16, borderBottom: '1px solid #e9ecef' }}>{toolbar}</div> : null}
      {data.length === 0 ? (
        <div style={{ padding: 16 }}>
          <EmptyState title={emptyTitle} message={emptyMessage} />
        </div>
      ) : (
        <>
          <div className="vb-table-wrap">
            <Table striped highlightOnHover className="vb-table">
              <Table.Thead>
                {table.getHeaderGroups().map((headerGroup) => (
                  <Table.Tr key={headerGroup.id}>
                    {headerGroup.headers.map((header) => (
                      <Table.Th key={header.id}>
                        {header.isPlaceholder ? null : header.column.getCanSort() ? (
                          <Group gap={4} wrap="nowrap">
                            {flexRender(header.column.columnDef.header, header.getContext())}
                            <Tooltip label="Change sort">
                              <ActionIcon
                                variant="subtle"
                                color="gray"
                                size="sm"
                                aria-label="Change sort"
                                onClick={header.column.getToggleSortingHandler()}
                              >
                                {header.column.getIsSorted() === 'asc' ? (
                                  <IconChevronUp size={14} />
                                ) : header.column.getIsSorted() === 'desc' ? (
                                  <IconChevronDown size={14} />
                                ) : (
                                  <IconArrowsSort size={14} />
                                )}
                              </ActionIcon>
                            </Tooltip>
                          </Group>
                        ) : (
                          flexRender(header.column.columnDef.header, header.getContext())
                        )}
                      </Table.Th>
                    ))}
                  </Table.Tr>
                ))}
              </Table.Thead>
              <Table.Tbody>
                {table.getRowModel().rows.map((row) => (
                  <Table.Tr key={row.id}>
                    {row.getVisibleCells().map((cell) => (
                      <Table.Td key={cell.id}>
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </Table.Td>
                    ))}
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </div>
          <Group justify="space-between" p="md" wrap="wrap">
            <Text size="sm" c="dimmed">
              {total.toLocaleString()} total
            </Text>
            {onPageChange && pageCount > 1 ? (
              <Pagination value={page} total={pageCount} onChange={onPageChange} />
            ) : null}
          </Group>
        </>
      )}
    </Paper>
  );
}
