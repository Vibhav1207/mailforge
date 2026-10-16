"use client";

import React, { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/context/auth-context";
import {
  getTemplates,
  saveTemplate,
  deleteTemplate,
} from "@/lib/store/db-service";
import { EmailTemplate, TemplateImage } from "@/types";
import { PREBUILT_TEMPLATES } from "@/lib/email/templates";
import { formatDate } from "@/lib/utils";
import {
  FileCode2,
  Plus,
  Copy,
  Trash2,
  Edit2,
  Eye,
  Send,
  X,
  Sparkles,
  Layers,
  CheckCircle2,
  Image as ImageIcon,
  UploadCloud,
  Folder,
  FolderPlus,
  ExternalLink,
  Code2,
  Database,
  Check,
} from "lucide-react";

export default function TemplatesPage() {
  const router = useRouter();
  const { user, profile } = useAuth();
  const userId = user?.uid || profile?.uid || "";

  const [templates, setTemplates] = useState<EmailTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [selectedFolder, setSelectedFolder] = useState<string>("all");

  // Preview Modal
  const [previewTemplate, setPreviewTemplate] = useState<EmailTemplate | null>(null);

  // Edit / Create Modal
  const [editModalOpen, setEditModalOpen] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<EmailTemplate | null>(null);
  const [modalName, setModalName] = useState("");
  const [modalSubject, setModalSubject] = useState("");
  const [modalCategory, setModalCategory] = useState<any>("custom");
  const [modalFolder, setModalFolder] = useState("general");
  const [modalImageUrl, setModalImageUrl] = useState("");
  const [modalDescription, setModalDescription] = useState("");
  const [modalHtml, setModalHtml] = useState("");
  const [uploadingImage, setUploadingImage] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // MongoDB Image Assets Library Modal
  const [imageLibraryOpen, setImageLibraryOpen] = useState(false);
  const [mongoImages, setMongoImages] = useState<TemplateImage[]>([]);
  const [loadingImages, setLoadingImages] = useState(false);
  const [libraryFolderFilter, setLibraryFolderFilter] = useState("all");
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const [uploadLibraryFolder, setUploadLibraryFolder] = useState("general");
  const [uploadingLibraryImg, setUploadingLibraryImg] = useState(false);

  const loadData = async () => {
    setLoading(true);
    try {
      // 1. Fetch templates from local/firebase store
      const data = await getTemplates(userId);

      // 2. Also try fetching templates from MongoDB /api/templates
      try {
        const mongoRes = await fetch("/api/templates");
        if (mongoRes.ok) {
          const mongoData = await mongoRes.json();
          if (mongoData.templates && mongoData.templates.length > 0) {
            // Merge MongoDB templates with prebuilt & local templates
            const existingIds = new Set(data.map((t) => t.id));
            for (const mt of mongoData.templates) {
              if (!existingIds.has(mt.id)) {
                data.push(mt);
              }
            }
          }
        }
      } catch (e) {
        console.warn("MongoDB templates fetch notice:", e);
      }

      setTemplates(data);
    } catch (err) {
      console.error("Load templates error:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadMongoImages = async (folder?: string) => {
    setLoadingImages(true);
    try {
      const q = folder && folder !== "all" ? `?folder=${encodeURIComponent(folder)}` : "";
      const res = await fetch(`/api/templates/images${q}`);
      if (res.ok) {
        const data = await res.json();
        setMongoImages(data.images || []);
      }
    } catch (err) {
      console.error("Failed to load MongoDB template images:", err);
    } finally {
      setLoadingImages(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [userId]);

  // Open Create Modal
  const handleOpenCreate = () => {
    setEditingTemplate(null);
    setModalName("");
    setModalSubject("");
    setModalCategory("custom");
    setModalFolder("general");
    setModalImageUrl("");
    setModalDescription("");
    setModalHtml(`<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; color: #1e293b; padding: 24px; max-width: 600px; margin: 0 auto;">
  <h2>Hello {{firstName}},</h2>
  <p>Your custom email content goes here.</p>
  <p>Best regards,<br>{{fromName}}</p>
</body>
</html>`);
    setEditModalOpen(true);
  };

  // Open Edit Modal
  const handleOpenEdit = (t: EmailTemplate) => {
    setEditingTemplate(t);
    setModalName(t.name);
    setModalSubject(t.subject);
    setModalCategory(t.category);
    setModalFolder(t.folder || "general");
    setModalImageUrl(t.imageUrl || "");
    setModalDescription(t.description || "");
    setModalHtml(t.htmlContent);
    setEditModalOpen(true);
  };

  // Upload image to MongoDB folder
  const handleImageFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadingImage(true);
    setUploadError(null);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("folder", modalFolder || "general");

      const res = await fetch("/api/templates/images", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Failed to upload image to MongoDB");
      }

      setModalImageUrl(data.image.url);
    } catch (err: any) {
      setUploadError(err.message || "Upload failed");
    } finally {
      setUploadingImage(false);
      e.target.value = "";
    }
  };

  // Insert image tag directly into HTML template
  const handleInsertImageIntoHtml = () => {
    if (!modalImageUrl) return;
    const imgTag = `\n<img src="${modalImageUrl}" alt="Template Banner" style="max-width: 100%; height: auto; border-radius: 8px; margin: 12px 0 20px 0; display: block;" />\n`;

    if (modalHtml.includes("<body") && modalHtml.includes(">")) {
      const idx = modalHtml.indexOf(">", modalHtml.indexOf("<body")) + 1;
      setModalHtml(modalHtml.slice(0, idx) + imgTag + modalHtml.slice(idx));
    } else {
      setModalHtml(imgTag + modalHtml);
    }
  };

  // Save Template
  const handleSaveTemplate = async (e: React.FormEvent) => {
    e.preventDefault();
    const toSave: EmailTemplate = {
      id: editingTemplate?.id || `tpl_custom_${Date.now()}`,
      userId,
      name: modalName,
      subject: modalSubject,
      category: modalCategory,
      folder: modalFolder || "general",
      imageUrl: modalImageUrl || undefined,
      description: modalDescription,
      htmlContent: modalHtml,
      createdAt: editingTemplate?.createdAt || new Date().toISOString(),
    };

    // Save locally/firebase
    await saveTemplate(toSave);

    // Sync to MongoDB
    try {
      await fetch("/api/templates", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(toSave),
      });
    } catch (err) {
      console.warn("MongoDB template save sync notice:", err);
    }

    setEditModalOpen(false);
    await loadData();
  };

  // Duplicate Template
  const handleDuplicate = async (t: EmailTemplate) => {
    const duplicated: EmailTemplate = {
      ...t,
      id: `tpl_custom_${Date.now()}`,
      userId,
      name: `${t.name} (Copy)`,
      createdAt: new Date().toISOString(),
    };
    await saveTemplate(duplicated);
    await loadData();
  };

  // Delete Template
  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this template?")) return;
    await deleteTemplate(userId, id);
    await loadData();
  };

  // Upload image in Library modal
  const handleLibraryUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadingLibraryImg(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("folder", uploadLibraryFolder);

      const res = await fetch("/api/templates/images", {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        await loadMongoImages(libraryFolderFilter);
      }
    } catch (err) {
      console.error("Library upload error:", err);
    } finally {
      setUploadingLibraryImg(false);
      e.target.value = "";
    }
  };

  // Delete image from MongoDB
  const handleDeleteImage = async (imageId: string) => {
    if (!confirm("Delete this image from MongoDB?")) return;
    try {
      const res = await fetch(`/api/templates/images/${imageId}`, {
        method: "DELETE",
      });
      if (res.ok) {
        await loadMongoImages(libraryFolderFilter);
      }
    } catch (err) {
      console.error("Delete image error:", err);
    }
  };

  // Extract unique folders
  const allFolders = Array.from(
    new Set(templates.map((t) => t.folder || "general"))
  ).filter(Boolean);

  const filtered = templates.filter((t) => {
    const matchCat = selectedCategory === "all" || t.category === selectedCategory;
    const matchFolder = selectedFolder === "all" || (t.folder || "general") === selectedFolder;
    return matchCat && matchFolder;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">Email Templates & Assets</h1>
          <p className="text-sm text-slate-500 mt-1">
            Build responsive email templates with optional banner images stored in MongoDB folders.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setImageLibraryOpen(true);
              loadMongoImages("all");
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-50 border border-slate-300 rounded-lg shadow-xs transition-all"
          >
            <Database className="w-3.5 h-3.5 text-emerald-600" />
            <span>MongoDB Image Folder</span>
          </button>

          <button
            onClick={handleOpenCreate}
            className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            <span>New Custom Template</span>
          </button>
        </div>
      </div>

      {/* Filter Bar: Categories & Folders */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-white p-3 rounded-xl border border-slate-200">
        {/* Category Filter Pills */}
        <div className="flex flex-wrap gap-1.5 text-xs">
          {[
            { id: "all", label: "All Templates" },
            { id: "outreach", label: "Cold Outreach" },
            { id: "event", label: "Events & Webinars" },
            { id: "announcement", label: "Announcements" },
            { id: "followup", label: "Follow-Up" },
            { id: "newsletter", label: "Newsletters" },
            { id: "custom", label: "Custom Saved" },
          ].map((cat) => (
            <button
              key={cat.id}
              onClick={() => setSelectedCategory(cat.id)}
              className={`px-3 py-1.5 rounded-lg font-medium transition-all ${
                selectedCategory === cat.id
                  ? "bg-slate-900 text-white shadow-xs"
                  : "bg-slate-50 text-slate-600 hover:bg-slate-100"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Folder Selector Dropdown */}
        {allFolders.length > 0 && (
          <div className="flex items-center gap-2 text-xs">
            <Folder className="w-3.5 h-3.5 text-slate-500" />
            <select
              value={selectedFolder}
              onChange={(e) => setSelectedFolder(e.target.value)}
              className="px-2.5 py-1.5 text-xs border border-slate-300 rounded-lg bg-white font-medium text-slate-700 focus:ring-1 focus:ring-blue-500"
            >
              <option value="all">All Folders</option>
              {allFolders.map((f) => (
                <option key={f} value={f}>
                  Folder: {f}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Templates Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filtered.map((t) => (
          <div
            key={t.id}
            className="bg-white rounded-xl border border-slate-200 shadow-sm flex flex-col justify-between hover:border-slate-300 transition-all overflow-hidden group"
          >
            {/* Optional Header Banner Image Stored in MongoDB */}
            {t.imageUrl && (
              <div className="w-full h-36 bg-slate-100 relative overflow-hidden border-b border-slate-200">
                <img
                  src={t.imageUrl}
                  alt={t.name}
                  className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                />
                <div className="absolute top-2 left-2 flex items-center gap-1 bg-black/60 backdrop-blur-xs text-white text-[10px] px-2 py-0.5 rounded font-mono">
                  <Database className="w-2.5 h-2.5 text-emerald-400" />
                  <span>MongoDB Asset</span>
                </div>
              </div>
            )}

            <div className="p-5 flex-1 flex flex-col justify-between space-y-4">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5">
                    <span className="text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-blue-50 text-blue-700 border border-blue-200">
                      {t.category}
                    </span>
                    {t.folder && (
                      <span className="text-[10px] font-medium text-slate-600 bg-slate-100 px-2 py-0.5 rounded border border-slate-200 flex items-center gap-1">
                        <Folder className="w-2.5 h-2.5 text-slate-500" />
                        {t.folder}
                      </span>
                    )}
                  </div>

                  {!t.userId && (
                    <span className="text-[10px] text-slate-400 font-medium">Pre-Built</span>
                  )}
                </div>

                <h3 className="text-base font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                  {t.name}
                </h3>
                <p className="text-xs text-slate-500 mt-1 line-clamp-2">
                  {t.description || "Reusable responsive email template."}
                </p>

                <div className="mt-3 p-2 bg-slate-50 rounded-lg border border-slate-100">
                  <span className="text-[11px] text-slate-500 font-medium block">Default Subject:</span>
                  <span className="text-xs font-semibold text-slate-800 line-clamp-1">
                    {t.subject}
                  </span>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-slate-100 flex items-center justify-between">
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setPreviewTemplate(t)}
                    title="Preview Template"
                    className="p-1.5 text-slate-500 hover:text-slate-800 hover:bg-slate-100 rounded-lg transition-colors"
                  >
                    <Eye className="w-4 h-4" />
                  </button>

                  <button
                    onClick={() => handleDuplicate(t)}
                    title="Duplicate Template"
                    className="p-1.5 text-slate-500 hover:text-slate-800 hover:bg-slate-100 rounded-lg transition-colors"
                  >
                    <Copy className="w-4 h-4" />
                  </button>

                  {t.userId && (
                    <>
                      <button
                        onClick={() => handleOpenEdit(t)}
                        title="Edit Template"
                        className="p-1.5 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleDelete(t.id)}
                        title="Delete Template"
                        className="p-1.5 text-slate-500 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </>
                  )}
                </div>

                <button
                  onClick={() => router.push(`/dashboard/compose?templateId=${t.id}`)}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-blue-600 hover:text-blue-700 bg-blue-50 hover:bg-blue-100 rounded-lg transition-colors"
                >
                  <Send className="w-3 h-3" />
                  <span>Use in Campaign</span>
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* EDIT / CREATE TEMPLATE MODAL */}
      {editModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-4 my-8">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div>
                <h2 className="text-base font-bold text-slate-900">
                  {editingTemplate ? "Edit Email Template" : "Create New Custom Template"}
                </h2>
                <p className="text-xs text-slate-500">
                  Define your template code, folder organization, and optional MongoDB image banner.
                </p>
              </div>
              <button
                onClick={() => setEditModalOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-600 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveTemplate} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2">
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Template Name
                  </label>
                  <input
                    type="text"
                    required
                    value={modalName}
                    onChange={(e) => setModalName(e.target.value)}
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500"
                    placeholder="e.g. Q4 Customer Outreach"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-700 mb-1">
                    Category
                  </label>
                  <select
                    value={modalCategory}
                    onChange={(e) => setModalCategory(e.target.value)}
                    className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500 bg-white"
                  >
                    <option value="custom">Custom</option>
                    <option value="outreach">Cold Outreach</option>
                    <option value="event">Event / Webinar</option>
                    <option value="announcement">Product Announcement</option>
                    <option value="newsletter">Newsletter</option>
                  </select>
                </div>
              </div>

              {/* Folder & Optional MongoDB Image Section */}
              <div className="p-4 bg-slate-50 rounded-xl border border-slate-200 space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1 flex items-center gap-1">
                      <Folder className="w-3.5 h-3.5 text-blue-600" />
                      <span>Template Folder (Optional)</span>
                    </label>
                    <input
                      type="text"
                      value={modalFolder}
                      onChange={(e) => setModalFolder(e.target.value)}
                      placeholder="e.g. newsletters, promotions, banners"
                      className="w-full px-3 py-1.5 text-xs border border-slate-300 rounded-lg bg-white"
                    />
                    <p className="text-[10.5px] text-slate-500 mt-1">
                      Group templates into folders in MongoDB.
                    </p>
                  </div>

                  <div>
                    <label className="block text-xs font-semibold text-slate-700 mb-1 flex items-center justify-between">
                      <span className="flex items-center gap-1">
                        <ImageIcon className="w-3.5 h-3.5 text-blue-600" />
                        <span>Header Image / Banner (Optional)</span>
                      </span>
                      <span className="text-[10px] text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-200">
                        MongoDB Stored
                      </span>
                    </label>

                    <div className="flex items-center gap-2">
                      <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-white border border-slate-300 rounded-lg hover:bg-slate-100 transition-colors shadow-2xs">
                        <UploadCloud className="w-3.5 h-3.5 text-blue-600" />
                        <span>{uploadingImage ? "Uploading..." : "Upload to MongoDB"}</span>
                        <input
                          type="file"
                          accept="image/*"
                          onChange={handleImageFileChange}
                          disabled={uploadingImage}
                          className="hidden"
                        />
                      </label>

                      <input
                        type="text"
                        value={modalImageUrl}
                        onChange={(e) => setModalImageUrl(e.target.value)}
                        placeholder="Or enter image URL"
                        className="flex-1 px-3 py-1.5 text-xs border border-slate-300 rounded-lg bg-white font-mono"
                      />
                    </div>

                    {uploadError && (
                      <p className="text-[11px] text-rose-600 mt-1">{uploadError}</p>
                    )}
                  </div>
                </div>

                {/* Image Preview & HTML Insertion Helper */}
                {modalImageUrl && (
                  <div className="flex items-center justify-between p-2.5 bg-white border border-slate-200 rounded-lg">
                    <div className="flex items-center gap-3">
                      <img
                        src={modalImageUrl}
                        alt="Preview"
                        className="w-14 h-10 object-cover rounded border border-slate-200"
                      />
                      <div>
                        <span className="text-[11px] font-semibold text-slate-800 block">
                          Image active for template
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono truncate max-w-xs block">
                          {modalImageUrl}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleInsertImageIntoHtml}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-semibold text-blue-700 bg-blue-50 hover:bg-blue-100 border border-blue-200 rounded transition-colors"
                      >
                        <Code2 className="w-3 h-3" />
                        <span>Insert into HTML Code</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setModalImageUrl("")}
                        className="text-slate-400 hover:text-rose-600 p-1"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Default Subject Line
                </label>
                <input
                  type="text"
                  required
                  value={modalSubject}
                  onChange={(e) => setModalSubject(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500"
                  placeholder="Special Invitation for {{firstName}}"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-700 mb-1">
                  Description
                </label>
                <input
                  type="text"
                  value={modalDescription}
                  onChange={(e) => setModalDescription(e.target.value)}
                  className="w-full px-3 py-2 text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500"
                  placeholder="Short note on what this template is for"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-xs font-semibold text-slate-700">
                    HTML Template Code
                  </label>
                  <span className="text-[11px] text-slate-500 font-mono">
                    Variables: {"{{firstName}}"}, {"{{company}}"}, {"{{fromName}}"}
                  </span>
                </div>
                <textarea
                  rows={9}
                  required
                  value={modalHtml}
                  onChange={(e) => setModalHtml(e.target.value)}
                  className="w-full p-2.5 font-mono text-xs border border-slate-300 rounded-lg focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setEditModalOpen(false)}
                  className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm"
                >
                  Save Template
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MONGODB IMAGE ASSETS LIBRARY MODAL */}
      {imageLibraryOpen && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-white rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-4 my-8">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div>
                <div className="flex items-center gap-2">
                  <Database className="w-5 h-5 text-emerald-600" />
                  <h2 className="text-base font-bold text-slate-900">
                    MongoDB Template Image Assets
                  </h2>
                </div>
                <p className="text-xs text-slate-500 mt-0.5">
                  Images stored in MongoDB collections, categorized into template folders.
                </p>
              </div>
              <button
                onClick={() => setImageLibraryOpen(false)}
                className="p-1 text-slate-400 hover:text-slate-600 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Upload image to specific folder */}
            <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <Folder className="w-4 h-4 text-blue-600" />
                <span className="font-semibold text-slate-700">Target Folder:</span>
                <input
                  type="text"
                  value={uploadLibraryFolder}
                  onChange={(e) => setUploadLibraryFolder(e.target.value)}
                  placeholder="general, banners, promos..."
                  className="px-2.5 py-1 text-xs border border-slate-300 rounded bg-white w-40 font-mono"
                />
              </div>

              <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors shadow-xs">
                <UploadCloud className="w-3.5 h-3.5" />
                <span>{uploadingLibraryImg ? "Uploading to MongoDB..." : "Upload New Image"}</span>
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleLibraryUpload}
                  disabled={uploadingLibraryImg}
                  className="hidden"
                />
              </label>
            </div>

            {/* Filter images by folder */}
            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-500 font-medium">Filter by folder:</span>
              {["all", "general", "banners", "newsletters", "promotions"].map((f) => (
                <button
                  key={f}
                  onClick={() => {
                    setLibraryFolderFilter(f);
                    loadMongoImages(f);
                  }}
                  className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                    libraryFolderFilter === f
                      ? "bg-slate-900 text-white"
                      : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>

            {/* Images Grid */}
            {loadingImages ? (
              <div className="py-12 text-center text-xs text-slate-500">
                Loading MongoDB image records...
              </div>
            ) : mongoImages.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-500 border border-dashed border-slate-200 rounded-xl space-y-2">
                <ImageIcon className="w-8 h-8 text-slate-300 mx-auto" />
                <p>No template images found in this folder in MongoDB.</p>
                <p className="text-[11px] text-slate-400">
                  Upload images above to store them directly in MongoDB!
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 max-h-96 overflow-y-auto p-1">
                {mongoImages.map((img) => (
                  <div
                    key={img.id}
                    className="border border-slate-200 rounded-xl overflow-hidden bg-white shadow-2xs group flex flex-col justify-between"
                  >
                    <div className="h-28 bg-slate-100 relative overflow-hidden">
                      <img
                        src={img.url}
                        alt={img.filename}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                      />
                      <span className="absolute bottom-1 left-1 bg-black/60 text-white text-[9px] px-1.5 py-0.5 rounded font-mono">
                        📁 {img.folder || "general"}
                      </span>
                    </div>

                    <div className="p-2.5 text-xs space-y-2">
                      <p className="font-semibold text-slate-800 truncate" title={img.filename}>
                        {img.filename}
                      </p>

                      <div className="flex items-center justify-between pt-1 border-t border-slate-100">
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(img.url);
                            setCopiedUrl(img.id);
                            setTimeout(() => setCopiedUrl(null), 2000);
                          }}
                          className="inline-flex items-center gap-1 text-[11px] font-semibold text-blue-600 hover:text-blue-800"
                        >
                          {copiedUrl === img.id ? (
                            <Check className="w-3 h-3 text-emerald-600" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          <span>{copiedUrl === img.id ? "Copied" : "Copy URL"}</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => handleDeleteImage(img.id)}
                          className="text-slate-400 hover:text-rose-600 p-1"
                          title="Delete from MongoDB"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-100">
              <button
                type="button"
                onClick={() => setImageLibraryOpen(false)}
                className="px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 rounded-lg"
              >
                Close Library
              </button>
            </div>
          </div>
        </div>
      )}

      {/* PREVIEW TEMPLATE MODAL */}
      {previewTemplate && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div>
                <h2 className="text-base font-bold text-slate-900">{previewTemplate.name}</h2>
                <p className="text-xs text-slate-500 font-mono">{previewTemplate.subject}</p>
              </div>
              <button
                onClick={() => setPreviewTemplate(null)}
                className="p-1 text-slate-400 hover:text-slate-600 rounded-lg"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto border border-slate-200 rounded-xl p-4 bg-slate-50/50">
              <iframe
                title="Preview"
                srcDoc={previewTemplate.htmlContent}
                className="w-full min-h-[380px] bg-white rounded-lg border border-slate-200"
              />
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-slate-400">
                Created: {formatDate(previewTemplate.createdAt)}
              </span>
              <button
                onClick={() => {
                  router.push(`/dashboard/compose?templateId=${previewTemplate.id}`);
                  setPreviewTemplate(null);
                }}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-lg shadow-sm"
              >
                <Send className="w-3.5 h-3.5" />
                <span>Use in Campaign</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
