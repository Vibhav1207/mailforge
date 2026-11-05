import { describe, it, expect } from "vitest";
import * as XLSX from "xlsx";
import { parseSpreadsheetFile, sanitizeFieldName } from "../src/lib/spreadsheet";
import { interpolateVariables } from "../src/lib/utils";

describe("Spreadsheet Parser & Field Extraction", () => {
  it("sanitizes field names into valid variable keys", () => {
    expect(sanitizeFieldName("First Name")).toBe("first_name");
    expect(sanitizeFieldName("Order ID #")).toBe("order_id");
    expect(sanitizeFieldName("Total Amount ($)")).toBe("total_amount");
    expect(sanitizeFieldName("  user-role  ")).toBe("user_role");
  });

  it("parses Excel buffer with email, full name, company, and custom columns", async () => {
    // Generate an in-memory workbook with SheetJS
    const data = [
      {
        "Full Name": "Alice Johnson",
        "E-Mail": "alice@example.com",
        "Company Name": "TechCorp Inc",
        "Role": "Lead Engineer",
        "Plan Type": "Enterprise",
      },
      {
        "Full Name": "Bob Smith",
        "E-Mail": "bob@example.com",
        "Company Name": "Innovate LLC",
        "Role": "Product Manager",
        "Plan Type": "Pro",
      },
      {
        // Missing / invalid email row
        "Full Name": "Ghost User",
        "E-Mail": "not-an-email",
        "Company Name": "Nowhere",
      },
      {
        // Duplicate email
        "Full Name": "Alice Dup",
        "E-Mail": "alice@example.com",
        "Company Name": "TechCorp",
      },
    ];

    const worksheet = XLSX.utils.json_to_sheet(data);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Recipients");
    const arrayBuffer = XLSX.write(workbook, { type: "array", bookType: "xlsx" });

    // Mock File object
    const file = new File([arrayBuffer], "recipients.xlsx", {
      type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    });

    const result = await parseSpreadsheetFile(file);

    expect(result.totalRows).toBe(4);
    expect(result.recipients.length).toBe(2);
    expect(result.duplicateCount).toBe(1);
    expect(result.invalidEmails).toContain("not-an-email");

    const alice = result.recipients.find((r) => r.email === "alice@example.com");
    expect(alice).toBeDefined();
    expect(alice?.name).toBe("Alice Johnson");
    expect(alice?.firstName).toBe("Alice");
    expect(alice?.lastName).toBe("Johnson");
    expect(alice?.company).toBe("TechCorp Inc");
    expect(alice?.customFields?.role).toBe("Lead Engineer");
    expect(alice?.customFields?.plan_type).toBe("Enterprise");
  });
});

describe("Template Variable Personalization & Interpolation", () => {
  it("interpolates {{name}}, {{firstName}}, {{lastName}}, {{company}}, {{email}} seamlessly", () => {
    const template = "Hello {{name}}, welcome to {{company}}! Your email is {{email}}.";
    const vars = {
      name: "Sarah Connor",
      firstName: "Sarah",
      lastName: "Connor",
      company: "Cyberdyne Systems",
      email: "sarah@cyberdyne.com",
    };

    const rendered = interpolateVariables(template, vars);
    expect(rendered).toBe("Hello Sarah Connor, welcome to Cyberdyne Systems! Your email is sarah@cyberdyne.com.");
  });

  it("handles case-insensitive and space variations in variable tags", () => {
    const template = "Hi {{ First Name }}, from {{ Company Name }} regarding order {{ Order_ID }}!";
    const vars = {
      firstName: "John",
      company: "Stark Industries",
      customFields: {
        order_id: "ORD-9981",
      },
    };

    const rendered = interpolateVariables(template, vars);
    expect(rendered).toBe("Hi John, from Stark Industries regarding order ORD-9981!");
  });

  it("falls back gracefully when firstName is requested but only name is provided, and vice versa", () => {
    const template1 = "Hello {{firstName}}!";
    const template2 = "Welcome {{name}}!";

    expect(interpolateVariables(template1, { name: "Tony Stark", email: "tony@avengers.org" })).toBe("Hello Tony!");
    expect(interpolateVariables(template2, { firstName: "Bruce", lastName: "Banner", email: "hulk@avengers.org" })).toBe("Welcome Bruce Banner!");
  });
});
