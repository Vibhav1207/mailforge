import * as XLSX from "xlsx";
import { isValidEmail } from "@/lib/utils";

export interface ParsedSpreadsheetRecipient {
  id: string;
  email: string;
  name?: string;
  firstName?: string;
  lastName?: string;
  company?: string;
  customFields?: Record<string, string>;
  selected?: boolean;
}

export interface SpreadsheetColumnDetection {
  emailColumn?: string;
  nameColumn?: string;
  firstNameColumn?: string;
  lastNameColumn?: string;
  companyColumn?: string;
  customColumns: string[];
  allColumns: string[];
}

export interface ParsedSpreadsheetResult {
  recipients: ParsedSpreadsheetRecipient[];
  invalidEmails: string[];
  duplicateCount: number;
  detection: SpreadsheetColumnDetection;
  sheetName: string;
  availableSheets: string[];
  fileName: string;
  totalRows: number;
}

/**
 * Clean & normalize a column key into a safe customField variable name (e.g. "Order ID" -> "order_id")
 */
export function sanitizeFieldName(rawKey: string): string {
  const cleaned = rawKey
    .trim()
    .replace(/[^\w]/g, "_")
    .replace(/^_+|_+$/g, "")
    .toLowerCase();
  return cleaned || "field";
}

/**
 * Parse an uploaded spreadsheet file (.xlsx, .xls, .csv, .tsv) into validated recipients
 */
export async function parseSpreadsheetFile(
  file: File,
  targetSheetName?: string
): Promise<ParsedSpreadsheetResult> {
  const arrayBuffer = await file.arrayBuffer();
  const workbook = XLSX.read(arrayBuffer, {
    type: "array",
    cellDates: true,
    cellText: false,
    raw: false,
  });

  const availableSheets = workbook.SheetNames || [];
  if (availableSheets.length === 0) {
    throw new Error("The uploaded spreadsheet contains no sheets.");
  }

  const selectedSheetName =
    targetSheetName && availableSheets.includes(targetSheetName)
      ? targetSheetName
      : availableSheets[0];

  const worksheet = workbook.Sheets[selectedSheetName];
  if (!worksheet) {
    throw new Error(`Sheet "${selectedSheetName}" could not be read.`);
  }

  // Convert worksheet to array of row objects
  const rawRows: Record<string, any>[] = XLSX.utils.sheet_to_json(worksheet, {
    defval: "",
    raw: false,
  });

  if (!rawRows || rawRows.length === 0) {
    return {
      recipients: [],
      invalidEmails: [],
      duplicateCount: 0,
      detection: { customColumns: [], allColumns: [] },
      sheetName: selectedSheetName,
      availableSheets,
      fileName: file.name,
      totalRows: 0,
    };
  }

  // Detect columns from first few rows
  const allColumns = Object.keys(rawRows[0] || {});
  const lowerCols = allColumns.map((c) => ({
    orig: c,
    lower: c.toLowerCase().trim().replace(/[\s_\-]+/g, ""),
  }));

  // Match Email column
  const emailMatch = lowerCols.find(
    (c) =>
      c.lower === "email" ||
      c.lower === "emailaddress" ||
      c.lower === "e-mail" ||
      c.lower === "mail" ||
      c.lower.includes("email") ||
      c.lower === "recipient" ||
      c.lower === "to"
  );
  const emailCol = emailMatch?.orig;

  // Match Name columns
  const nameMatch = lowerCols.find(
    (c) =>
      c.lower === "name" ||
      c.lower === "fullname" ||
      c.lower === "contactname" ||
      c.lower === "clientname" ||
      c.lower === "customername" ||
      c.lower === "recipientname" ||
      c.lower === "displayname"
  );
  const firstNameMatch = lowerCols.find(
    (c) =>
      c.lower === "firstname" ||
      c.lower === "fname" ||
      c.lower === "first" ||
      c.lower === "givenname"
  );
  const lastNameMatch = lowerCols.find(
    (c) =>
      c.lower === "lastname" ||
      c.lower === "lname" ||
      c.lower === "last" ||
      c.lower === "surname" ||
      c.lower === "familyname"
  );

  // Match Company column
  const companyMatch = lowerCols.find(
    (c) =>
      c.lower === "company" ||
      c.lower === "companyname" ||
      c.lower === "organization" ||
      c.lower === "org" ||
      c.lower === "business" ||
      c.lower === "employer"
  );

  const matchedKeys = new Set<string>(
    [
      emailCol,
      nameMatch?.orig,
      firstNameMatch?.orig,
      lastNameMatch?.orig,
      companyMatch?.orig,
    ].filter(Boolean) as string[]
  );

  // Remaining columns become custom variables
  const customCols = allColumns.filter((c) => !matchedKeys.has(c));

  const validRecipients: ParsedSpreadsheetRecipient[] = [];
  const invalidEmails: string[] = [];
  const seenEmails = new Set<string>();
  let duplicateCount = 0;

  for (let i = 0; i < rawRows.length; i++) {
    const row = rawRows[i];

    // Determine email address for this row
    let rawEmail = "";
    if (emailCol && row[emailCol]) {
      rawEmail = String(row[emailCol]).trim().toLowerCase();
    } else {
      // Fallback: search all cell values in row for a valid email
      for (const col of allColumns) {
        const val = String(row[col] || "").trim().toLowerCase();
        if (isValidEmail(val)) {
          rawEmail = val;
          break;
        }
      }
    }

    if (!rawEmail) {
      // Row might be empty or missing email
      continue;
    }

    if (!isValidEmail(rawEmail)) {
      invalidEmails.push(rawEmail);
      continue;
    }

    if (seenEmails.has(rawEmail)) {
      duplicateCount++;
      continue;
    }
    seenEmails.add(rawEmail);

    // Extract Name details
    let firstName = "";
    let lastName = "";
    let fullName = "";

    if (firstNameMatch && row[firstNameMatch.orig]) {
      firstName = String(row[firstNameMatch.orig]).trim();
    }
    if (lastNameMatch && row[lastNameMatch.orig]) {
      lastName = String(row[lastNameMatch.orig]).trim();
    }

    if (nameMatch && row[nameMatch.orig]) {
      fullName = String(row[nameMatch.orig]).trim();
      if (!firstName && fullName) {
        const parts = fullName.split(/\s+/);
        firstName = parts[0] || "";
        lastName = parts.slice(1).join(" ") || "";
      }
    } else if (firstName || lastName) {
      fullName = [firstName, lastName].filter(Boolean).join(" ");
    }

    const company = companyMatch && row[companyMatch.orig]
      ? String(row[companyMatch.orig]).trim()
      : "";

    // Build custom fields dictionary
    const customFields: Record<string, string> = {};
    for (const col of customCols) {
      const val = row[col];
      if (val !== undefined && val !== null && val !== "") {
        const strVal = String(val).trim();
        // Set both sanitized key and direct trimmed key so templates can use either {{order_id}} or {{Order ID}}
        const sanitizedKey = sanitizeFieldName(col);
        customFields[sanitizedKey] = strVal;
        if (sanitizedKey !== col.trim()) {
          customFields[col.trim()] = strVal;
        }
      }
    }

    validRecipients.push({
      id: `rcp_${Date.now()}_${i}_${Math.random().toString(36).substring(2, 6)}`,
      email: rawEmail,
      name: fullName,
      firstName,
      lastName,
      company,
      customFields,
      selected: true,
    });
  }

  return {
    recipients: validRecipients,
    invalidEmails,
    duplicateCount,
    detection: {
      emailColumn: emailCol,
      nameColumn: nameMatch?.orig,
      firstNameColumn: firstNameMatch?.orig,
      lastNameColumn: lastNameMatch?.orig,
      companyColumn: companyMatch?.orig,
      customColumns: customCols,
      allColumns,
    },
    sheetName: selectedSheetName,
    availableSheets,
    fileName: file.name,
    totalRows: rawRows.length,
  };
}
