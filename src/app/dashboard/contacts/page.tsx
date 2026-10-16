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

  const loadContactsData = async () => {
    setLoading(true);
    try {
      const data = await getContacts(userId);
      setContacts(data);
    } catch (err) {
      console.error("Failed to load contacts:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
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

  // CSV Import File Handler
  const handleCsvFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    Papa.parse<any>(file, {
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        setCsvPreviewRows(results.data.slice(0, 5));
        setCsvTotalCount(results.data.length);
        (window as any).__parsedCsvRows = results.data;
      },
    });
  };

  // Commit CSV Import
  const handleCommitCsvImport = async () => {
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
    link.setAttribute("download", `mailforge_contacts_${new Date().toISOString().slice(0, 10)}.csv`);
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

  // Extract unique tags
  const allTags = Array.from(new Set(contacts.flatMap((c) => c.tags || [])));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Contacts Management</h1>
          <p className="text-sm text-slate-500 mt-1">
            Audience lists, suppression status, and CSV import/export controls.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleExportCsv}
            disabled={contacts.length === 0}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 shadow-sm transition-all disabled:opacity-50"
          >
            <Download className="w-4 h-4 text-slate-500" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={() => setImportModalOpen(true)}
            className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white border border-slate-300 rounded-lg hover:bg-slate-50 shadow-sm transition-all"
          >
            <Upload className="w-4 h-4 text-slate-500" />
            <span>Import CSV</span>
          </button>

          <button
            onClick={openAddModal}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>Add Contact</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-col sm:flex-row gap-3 items-center justify-between">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by name, email, company..."
            className="w-full pl-9 pr-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto">
          {/* Status filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white text-slate-700"
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
              className="px-2.5 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white text-slate-700"
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
      <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-xs text-slate-500">Loading contacts...</div>
        ) : filteredContacts.length === 0 ? (
          <div className="p-12 text-center">
            <Users className="w-10 h-10 text-slate-300 mx-auto mb-3" />
            <h3 className="text-sm font-semibold text-slate-900">No contacts found</h3>
            <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
              Add contacts manually or import a CSV file to begin sending.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 font-semibold uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-4">Contact</th>
                  <th className="py-3 px-4">Company</th>
                  <th className="py-3 px-4">Tags</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredContacts.map((c) => {
                  const statusBadge: Record<string, { label: string; class: string }> = {
                    active: { label: "Active", class: "bg-emerald-50 text-emerald-700 border-emerald-200" },
                    unsubscribed: { label: "Unsubscribed", class: "bg-amber-50 text-amber-700 border-amber-200" },
                    suppressed: { label: "Suppressed", class: "bg-red-50 text-red-700 border-red-200" },
                  };

                  const badge = statusBadge[c.status] || statusBadge.active;

                  return (
                    <tr key={c.id} className="hover:bg-slate-50/60 transition-colors">
                      <td className="py-3 px-4">
                        <p className="font-semibold text-slate-900">
                          {[c.firstName, c.lastName].filter(Boolean).join(" ") || "—"}
                        </p>
                        <p className="font-mono text-slate-500 text-[11px]">{c.email}</p>
                      </td>
                      <td className="py-3 px-4 text-slate-700">{c.company || "—"}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1">
                          {(c.tags || []).length > 0 ? (
                            c.tags!.map((t) => (
                              <span
                                key={t}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-slate-100 text-slate-600 font-medium"
                              >
                                {t}
                              </span>
                            ))
                          ) : (
                            <span className="text-slate-400">—</span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold border uppercase ${badge.class}`}
                        >
                          {badge.label}
                        </span>
                        {c.suppressionReason && (
                          <p className="text-[10px] text-slate-400 mt-0.5 truncate max-w-xs">
                            {c.suppressionReason}
                          </p>
                        )}
                      </td>
                      <td className="py-3 px-4 text-slate-500">{formatDate(c.createdAt)}</td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          onClick={() => openEditModal(c)}
                          className="p-1 text-slate-400 hover:text-blue-600"
                          title="Edit Contact"
                        >
                          <Edit2 className="w-3.5 h-3.5 inline" />
                        </button>
                        <button
                          onClick={() => handleDeleteContact(c.id)}
                          className="p-1 text-slate-400 hover:text-red-600"
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
      {contactModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-base font-bold text-slate-900">
                {editingContact ? "Edit Contact" : "Add New Contact"}
              </h3>
              <button onClick={() => setContactModalOpen(false)} className="p-1 text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-50 border border-red-200 text-red-700 text-xs rounded-lg flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleSaveContact} className="space-y-3">
              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Email Address *
                </label>
                <input
                  type="email"
                  required
                  value={modalEmail}
                  onChange={(e) => setModalEmail(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                  placeholder="contact@company.com"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    First Name
                  </label>
                  <input
                    type="text"
                    value={modalFirstName}
                    onChange={(e) => setModalFirstName(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                    placeholder="Alex"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Last Name
                  </label>
                  <input
                    type="text"
                    value={modalLastName}
                    onChange={(e) => setModalLastName(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                    placeholder="Mercer"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Company
                </label>
                <input
                  type="text"
                  value={modalCompany}
                  onChange={(e) => setModalCompany(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                  placeholder="Apex Tech"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Tags (comma separated)
                </label>
                <input
                  type="text"
                  value={modalTags}
                  onChange={(e) => setModalTags(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 focus:outline-none"
                  placeholder="VIP, Engineering, Enterprise"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Status
                </label>
                <select
                  value={modalStatus}
                  onChange={(e) => setModalStatus(e.target.value as ContactStatus)}
                  className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white"
                >
                  <option value="active">Active (Deliverable)</option>
                  <option value="unsubscribed">Unsubscribed (Excluded from sends)</option>
                  <option value="suppressed">Suppressed / Bounced (Excluded)</option>
                </select>
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setContactModalOpen(false)}
                  className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm"
                >
                  Save Contact
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Import CSV Contacts */}
      {importModalOpen && (
        <div className="fixed inset-0 z-50 bg-slate-900/50 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-white rounded-xl shadow-xl border border-slate-200 max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-base font-bold text-slate-900">Import Contacts from CSV</h3>
              <button onClick={() => setImportModalOpen(false)} className="p-1 text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            <label className="border-2 border-dashed border-slate-300 hover:border-blue-500 rounded-xl p-6 flex flex-col items-center justify-center cursor-pointer transition-colors text-center bg-slate-50">
              <FileSpreadsheet className="w-8 h-8 text-blue-600 mb-2" />
              <span className="text-xs font-semibold text-slate-800">
                Select CSV file to upload
              </span>
              <span className="text-[11px] text-slate-500 mt-1">
                CSV headers should include 'email', and optionally 'firstName', 'lastName', 'company'.
              </span>
              <input type="file" accept=".csv" onChange={handleCsvFile} className="hidden" />
            </label>

            {csvPreviewRows.length > 0 && (
              <div className="space-y-2">
                <div className="flex justify-between text-xs font-semibold text-slate-700">
                  <span>Preview ({csvTotalCount} rows detected):</span>
                </div>
                <div className="max-h-40 overflow-y-auto border border-slate-200 rounded-lg p-2 bg-slate-50 font-mono text-[11px]">
                  {csvPreviewRows.map((r, i) => (
                    <div key={i} className="truncate border-b border-slate-200/60 pb-1 mb-1">
                      {JSON.stringify(r)}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setImportModalOpen(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 rounded-lg"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleCommitCsvImport}
                disabled={csvTotalCount === 0}
                className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm disabled:opacity-50"
              >
                Import {csvTotalCount} Contacts
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
