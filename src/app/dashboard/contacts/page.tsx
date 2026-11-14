"use client";

import React, { useState, useEffect } from "react";
import Papa from "papaparse";
import { useAuth } from "@/context/auth-context";
import {
  getContacts,
  saveContact,
  deleteContact,
} from "@/lib/store/db-service";
import { Contact, ContactStatus } from "@/types";
import { formatDate, isValidEmail } from "@/lib/utils";
import { parseSpreadsheetFile } from "@/lib/spreadsheet";
import { motion, AnimatePresence } from "motion/react";
import {
  Users,
  Search,
  Upload,
  Download,
  Plus,
  Trash2,
  Edit2,
  Filter,
  CheckCircle2,
  AlertCircle,
  ShieldAlert,
  X,
  FileSpreadsheet,
} from "lucide-react";

export default function ContactsManagementPage() {
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [tagFilter, setTagFilter] = useState<string>("all");

  // Add / Edit Modal State
  const [contactModalOpen, setContactModalOpen] = useState(false);
  const [editingContact, setEditingContact] = useState<Contact | null>(null);
  const [modalEmail, setModalEmail] = useState("");
  const [modalFirstName, setModalFirstName] = useState("");
  const [modalLastName, setModalLastName] = useState("");
  const [modalCompany, setModalCompany] = useState("");
  const [modalTags, setModalTags] = useState("");
  const [modalStatus, setModalStatus] = useState<ContactStatus>("active");
  const [formError, setFormError] = useState<string | null>(null);

  // CSV Import Modal State
  const [importModalOpen, setImportModalOpen] = useState(false);
  const [csvPreviewRows, setCsvPreviewRows] = useState<any[]>([]);
  const [csvTotalCount, setCsvTotalCount] = useState(0);

  const loadContactsData = async (forceRefresh = false) => {
    if (!userId) return;
    setLoading(true);
    try {
      const data = await getContacts(userId, forceRefresh);
      setContacts(data);
    } catch (err) {
      console.error("Failed to load contacts:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!userId) return;
    loadContactsData();
  }, [userId]);

  // Open Add Modal
  const openAddModal = () => {
    setEditingContact(null);
    setModalEmail("");
    setModalFirstName("");
    setModalLastName("");
    setModalCompany("");
    setModalTags("");
    setModalStatus("active");
    setFormError(null);
    setContactModalOpen(true);
  };

  // Open Edit Modal
  const openEditModal = (c: Contact) => {
    setEditingContact(c);
    setModalEmail(c.email);
    setModalFirstName(c.firstName || "");
    setModalLastName(c.lastName || "");
    setModalCompany(c.company || "");
    setModalTags((c.tags || []).join(", "));
    setModalStatus(c.status);
    setFormError(null);
    setContactModalOpen(true);
  };

  // Save Contact Form Submission
  const handleSaveContact = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    if (!isValidEmail(modalEmail)) {
      setFormError("Please enter a valid email address.");
      return;
    }

    const tagsArray = modalTags
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);

    const contactToSave: Contact = {
      id: editingContact?.id || `c_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      userId,
      email: modalEmail.trim().toLowerCase(),
      firstName: modalFirstName.trim(),
      lastName: modalLastName.trim(),
      company: modalCompany.trim(),
      tags: tagsArray,
      status: modalStatus,
      suppressionReason:
        modalStatus !== "active"
          ? editingContact?.suppressionReason || "Manually updated by operator"
          : undefined,
      createdAt: editingContact?.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    try {
      await saveContact(contactToSave);
      setContactModalOpen(false);
      await loadContactsData();
    } catch (err: any) {
      setFormError(err.message || "Failed to save contact");
    }
  };

  // Delete Contact
  const handleDeleteContact = async (id: string) => {
    if (!confirm("Are you sure you want to delete this contact?")) return;
    try {
      await deleteContact(userId, id);
      await loadContactsData();
    } catch (err) {
      console.error("Delete contact error:", err);
    }
  };

  // Spreadsheet (.xlsx, .xls, .csv) Import File Handler
  const handleCsvFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const parsed = await parseSpreadsheetFile(file);
      setCsvPreviewRows(parsed.recipients.slice(0, 5));
      setCsvTotalCount(parsed.recipients.length);
      (window as any).__parsedSpreadsheetRecipients = parsed.recipients;
    } catch (err: any) {
      alert(err.message || "Failed to parse spreadsheet file");
    }
  };

  // Commit CSV / Spreadsheet Import
  const handleCommitCsvImport = async () => {
    const parsedRecipients = (window as any).__parsedSpreadsheetRecipients || [];
    if (parsedRecipients.length > 0) {
      const existingEmails = new Set(contacts.map((c) => c.email.toLowerCase()));
      let importedCount = 0;
      for (const r of parsedRecipients) {
        if (isValidEmail(r.email) && !existingEmails.has(r.email.toLowerCase())) {
          await saveContact({
            id: `c_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
            userId,
            email: r.email.toLowerCase(),
            firstName: r.firstName || "",
            lastName: r.lastName || "",
            company: r.company || "",
            customFields: r.customFields,
            tags: ["Spreadsheet Import"],
            status: "active",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          });
          existingEmails.add(r.email.toLowerCase());
          importedCount++;
        }
      }
      setImportModalOpen(false);
      setCsvPreviewRows([]);
      await loadContactsData();
      alert(`Successfully imported ${importedCount} new contacts.`);
      return;
    }

    const rows = (window as any).__parsedCsvRows || [];
    if (rows.length === 0) return;

    const existingEmails = new Set(contacts.map((c) => c.email.toLowerCase()));
    let importedCount = 0;

    for (const row of rows) {
      const emailKey = Object.keys(row).find((k) =>
        k.toLowerCase().includes("email") || k.toLowerCase() === "mail"
      );
      const rawEmail = emailKey ? String(row[emailKey] || "").trim().toLowerCase() : "";

      if (isValidEmail(rawEmail) && !existingEmails.has(rawEmail)) {
        const firstNameKey = Object.keys(row).find((k) =>
          k.toLowerCase().includes("first") || k.toLowerCase() === "name"
        );
        const lastNameKey = Object.keys(row).find((k) => k.toLowerCase().includes("last"));
        const companyKey = Object.keys(row).find((k) =>
          k.toLowerCase().includes("company") || k.toLowerCase().includes("org")
        );

        await saveContact({
          id: `c_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
          userId,
          email: rawEmail,
          firstName: firstNameKey ? row[firstNameKey] : "",
          lastName: lastNameKey ? row[lastNameKey] : "",
          company: companyKey ? row[companyKey] : "",
          tags: ["CSV Import"],
          status: "active",
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        });
        existingEmails.add(rawEmail);
        importedCount++;
      }
    }

    setImportModalOpen(false);
    setCsvPreviewRows([]);
    await loadContactsData();
    alert(`Successfully imported ${importedCount} new contacts.`);
  };

  // CSV Export Download
  const handleExportCsv = () => {
    const exportData = filteredContacts.map((c) => ({
      email: c.email,
      firstName: c.firstName || "",
      lastName: c.lastName || "",
      company: c.company || "",
      tags: (c.tags || []).join("; "),
      status: c.status,
      suppressionReason: c.suppressionReason || "",
      createdAt: c.createdAt,
    }));

    const csvString = Papa.unparse(exportData);
    const blob = new Blob([csvString], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `postvane_contacts_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Filtered contacts list
  const filteredContacts = contacts.filter((c) => {
    const matchesSearch =
      c.email.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (c.firstName && c.firstName.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (c.lastName && c.lastName.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (c.company && c.company.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesStatus = statusFilter === "all" || c.status === statusFilter;
    const matchesTag = tagFilter === "all" || (c.tags && c.tags.includes(tagFilter));

    return matchesSearch && matchesStatus && matchesTag;
  });

  const allTags = Array.from(new Set(contacts.flatMap((c) => c.tags || [])));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-medium tracking-tight text-white">Contacts Management</h1>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Audience directory, suppression states, and spreadsheet ingestion.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.97 }}
            transition={{ duration: 0.18 }}
            onClick={handleExportCsv}
            disabled={contacts.length === 0}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors disabled:opacity-40"
          >
            <Download className="w-3.5 h-3.5 text-zinc-400" />
            <span>Export CSV</span>
          </motion.button>

          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.97 }}
            transition={{ duration: 0.18 }}
            onClick={() => setImportModalOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors"
          >
            <Upload className="w-3.5 h-3.5 text-zinc-400" />
            <span>Import Excel / CSV</span>
          </motion.button>

          <motion.button
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.97 }}
            transition={{ duration: 0.18 }}
            onClick={openAddModal}
            className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Contact</span>
          </motion.button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#111315] p-3 rounded-xl border border-[#262A2E] flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search name, email, company..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none font-mono"
          />
        </div>

        <div className="flex items-center gap-2.5 w-full sm:w-auto">
          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs font-mono bg-[#171A1D] border border-[#262A2E] text-zinc-300 rounded-lg focus:outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active (Deliverable)</option>
            <option value="unsubscribed">Unsubscribed</option>
            <option value="suppressed">Suppressed / Bounced</option>
          </select>

          {/* Tag filter */}
          {allTags.length > 0 && (
            <select
              value={tagFilter}
              onChange={(e) => setTagFilter(e.target.value)}
              className="px-2.5 py-1.5 text-xs font-mono bg-[#171A1D] border border-[#262A2E] text-zinc-300 rounded-lg focus:outline-none"
            >
              <option value="all">All Tags</option>
              {allTags.map((t) => (
                <option key={t} value={t}>
                  Tag: {t}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {/* Contacts Table */}
      <div className="bg-[#111315] rounded-xl border border-[#262A2E] overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs font-mono text-zinc-500">
            LOADING AUDIENCE RECORDS...
          </div>
        ) : filteredContacts.length === 0 ? (
          <div className="p-12 text-center">
            <Users className="w-10 h-10 text-zinc-600 mx-auto mb-3" />
            <h3 className="text-sm font-medium text-white">No contacts found</h3>
            <p className="text-xs text-zinc-500 font-mono mt-1 max-w-sm mx-auto">
              Add contacts manually or import an Excel/CSV spreadsheet.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-[#171A1D]/60 border-b border-[#262A2E] text-zinc-400 font-mono text-[11px] uppercase tracking-wider">
                  <th className="py-3 px-4 font-medium">Contact</th>
                  <th className="py-3 px-4 font-medium">Company</th>
                  <th className="py-3 px-4 font-medium">Tags</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium">Created</th>
                  <th className="py-3 px-4 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1C2024]">
                {filteredContacts.map((c) => {
                  const statusColors: Record<string, string> = {
                    active: "border-emerald-500/30 bg-emerald-950/40 text-emerald-400",
                    unsubscribed: "border-amber-500/30 bg-amber-950/40 text-amber-400",
                    suppressed: "border-red-500/30 bg-red-950/40 text-red-400",
                  };

                  return (
                    <tr key={c.id} className="hover:bg-[#171A1D]/40 transition-colors">
                      <td className="py-3 px-4">
                        <p className="font-medium text-white">
                          {[c.firstName, c.lastName].filter(Boolean).join(" ") || "—"}
                        </p>
                        <p className="font-mono text-zinc-400 text-[11px]">{c.email}</p>
                      </td>
                      <td className="py-3 px-4 text-zinc-300">{c.company || "—"}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {(c.tags || []).length > 0 ? (
                            c.tags!.map((t) => (
                              <span
                                key={t}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-[#171A1D] border border-[#262A2E] text-zinc-300 font-mono"
                              >
                                {t}
                              </span>
                            ))
                          ) : (
                            <span className="text-zinc-600 font-mono text-[11px]">—</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-mono border uppercase ${
                            statusColors[c.status] || "border-zinc-700 bg-zinc-800 text-zinc-400"
                          }`}
                        >
                          {c.status}
                        </span>
                        {c.suppressionReason && (
                          <p className="text-[10px] text-zinc-500 font-mono mt-0.5 truncate max-w-xs">
                            {c.suppressionReason}
                          </p>
                        )}
                      </td>
                      <td className="py-3 px-4 text-zinc-400 font-mono text-[11px]">
                        {formatDate(c.createdAt)}
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => openEditModal(c)}
                          className="p-1 text-zinc-500 hover:text-white transition-colors"
                          title="Edit Contact"
                        >
                          <Edit2 className="w-3.5 h-3.5 inline" />
                        </button>
                        <button
                          onClick={() => handleDeleteContact(c.id)}
                          className="p-1 text-zinc-500 hover:text-red-400 transition-colors"
                          title="Delete Contact"
                        >
                          <Trash2 className="w-3.5 h-3.5 inline" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* MODAL: Add / Edit Contact */}
      <AnimatePresence>
        {contactModalOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 6 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
              className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-md w-full p-6 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-[#262A2E] pb-3">
                <h3 className="text-sm font-medium text-white">
                  {editingContact ? "Edit Contact" : "Add New Contact"}
                </h3>
                <button onClick={() => setContactModalOpen(false)} className="p-1 text-zinc-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>

            {formError && (
              <div className="p-3 bg-red-950/40 border border-red-500/30 text-red-400 text-xs rounded-lg flex items-center gap-2 font-mono">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleSaveContact} className="space-y-3">
              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  Email Address *
                </label>
                <input
                  type="email"
                  required
                  value={modalEmail}
                  onChange={(e) => setModalEmail(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white font-mono rounded-lg focus:border-zinc-500 focus:outline-none"
                  placeholder="contact@company.com"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    First Name
                  </label>
                  <input
                    type="text"
                    value={modalFirstName}
                    onChange={(e) => setModalFirstName(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                    placeholder="Alex"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    Last Name
                  </label>
                  <input
                    type="text"
                    value={modalLastName}
                    onChange={(e) => setModalLastName(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                    placeholder="Mercer"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  Company
                </label>
                <input
                  type="text"
                  value={modalCompany}
                  onChange={(e) => setModalCompany(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                  placeholder="Apex Tech"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  Tags (comma separated)
                </label>
                <input
                  type="text"
                  value={modalTags}
                  onChange={(e) => setModalTags(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white font-mono rounded-lg focus:border-zinc-500 focus:outline-none"
                  placeholder="VIP, Engineering, Enterprise"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  Status
                </label>
                <select
                  value={modalStatus}
                  onChange={(e) => setModalStatus(e.target.value as ContactStatus)}
                  className="w-full px-3 py-1.5 text-xs bg-[#171A1D] border border-[#262A2E] text-white font-mono rounded-lg focus:outline-none"
                >
                  <option value="active">Active (Deliverable)</option>
                  <option value="unsubscribed">Unsubscribed (Excluded)</option>
                  <option value="suppressed">Suppressed / Bounced (Excluded)</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#262A2E]">
                <button
                  type="button"
                  onClick={() => setContactModalOpen(false)}
                  className="px-4 py-2 text-xs font-mono text-zinc-400 hover:text-white rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors"
                >
                  Save Contact
                </button>
              </div>
            </form>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* MODAL: Import CSV Contacts */}
      <AnimatePresence>
        {importModalOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4"
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.96, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.97, y: 6 }}
              transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
              className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-lg w-full p-6 space-y-4"
            >
              <div className="flex items-center justify-between border-b border-[#262A2E] pb-3">
                <h3 className="text-sm font-medium text-white">Import Contacts from Excel or CSV</h3>
                <button onClick={() => setImportModalOpen(false)} className="p-1 text-zinc-400 hover:text-white">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <label className="border border-dashed border-[#262A2E] hover:border-zinc-500 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-colors text-center bg-[#171A1D]/40">
                <FileSpreadsheet className="w-8 h-8 text-zinc-400 mb-2" />
                <span className="text-xs font-medium text-white">
                  Select Excel (.xlsx, .xls) or CSV file
                </span>
                <span className="text-[11px] text-zinc-500 font-mono mt-1">
                  Auto-detects email, firstName, lastName, company, and custom fields.
                </span>
                <input type="file" accept=".xlsx,.xls,.csv,.tsv" onChange={handleCsvFile} className="hidden" />
              </label>

              {csvPreviewRows.length > 0 && (
                <div className="space-y-2">
                  <div className="flex justify-between text-xs font-mono text-zinc-400">
                    <span>Preview ({csvTotalCount} rows detected):</span>
                  </div>
                  <div className="max-h-40 overflow-y-auto border border-[#262A2E] rounded-lg p-2.5 bg-[#171A1D] font-mono text-[11px] text-zinc-300">
                    {csvPreviewRows.map((r, i) => (
                      <div key={i} className="truncate border-b border-[#262A2E] pb-1 mb-1">
                        {JSON.stringify(r)}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#262A2E]">
                <button
                  type="button"
                  onClick={() => setImportModalOpen(false)}
                  className="px-4 py-2 text-xs font-mono text-zinc-400 hover:text-white rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleCommitCsvImport}
                  disabled={csvTotalCount === 0}
                  className="px-4 py-2 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors disabled:opacity-40"
                >
                  Import {csvTotalCount} Contacts
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
