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
import { apiFetch } from "@/lib/api-client";
import { EmailTemplate, TemplateImage, EmailAttachment } from "@/types";
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
  Check,
  Paperclip,
  FileText,
  AlertCircle,
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
  const [modalAttachments, setModalAttachments] = useState<EmailAttachment[]>([]);
  const [modalAttachmentError, setModalAttachmentError] = useState<string | null>(null);

  // Asset Folders & Media Library Modal
  const [imageLibraryOpen, setImageLibraryOpen] = useState(false);
  const [libraryImages, setLibraryImages] = useState<TemplateImage[]>([]);
  const [loadingImages, setLoadingImages] = useState(false);
  const [libraryFolderFilter, setLibraryFolderFilter] = useState("all");
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);
  const [uploadLibraryFolder, setUploadLibraryFolder] = useState("general");
  const [uploadingLibraryImg, setUploadingLibraryImg] = useState(false);

  const loadData = async (forceRefresh = false) => {
    if (!userId) return;
    setLoading(true);
    try {
      const data = await getTemplates(userId, forceRefresh);
      setTemplates(data);
    } catch (err) {
      console.error("Load templates error:", err);
    } finally {
      setLoading(false);
    }
  };

  const loadLibraryImages = async (folder?: string) => {
    setLoadingImages(true);
    try {
      const q = folder && folder !== "all" ? `?folder=${encodeURIComponent(folder)}` : "";
      const res = await apiFetch(`/api/templates/images${q}`);
      if (res.ok) {
        const text = await res.text();
        const data = text ? JSON.parse(text) : {};
        setLibraryImages(data.images || []);
      }
    } catch (err) {
      console.error("Failed to load library images:", err);
    } finally {
      setLoadingImages(false);
    }
  };

  useEffect(() => {
    if (!userId) return;
    loadData();
  }, [userId]);

  const handleOpenCreate = () => {
    setEditingTemplate(null);
    setModalName("");
    setModalSubject("");
    setModalCategory("custom");
    setModalFolder("general");
    setModalImageUrl("");
    setModalDescription("");
    setModalAttachments([]);
    setModalAttachmentError(null);
    setModalHtml(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #111827; margin: 0; padding: 24px; }
    .container { max-width: 600px; margin: 0 auto; background: #ffffff; padding: 32px; border-radius: 8px; border: 1px solid #e5e7eb; }
    h1 { font-size: 20px; font-weight: 600; color: #111827; margin-top: 0; }
    p { margin: 16px 0; font-size: 14px; }
    .btn { display: inline-block; padding: 10px 20px; background-color: #000000; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 13px; }
    .footer { font-size: 12px; color: #6b7280; border-top: 1px solid #e5e7eb; padding-top: 16px; margin-top: 32px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Hello {{firstName}},</h1>
    <p>Write your message here. You can use dynamic variables like {{company}} or {{firstName}}.</p>
    <p><a href="https://example.com" class="btn">Take Action</a></p>
    <div class="footer">
      <p>Sent by {{fromName}}. <a href="{{unsubscribeUrl}}">Unsubscribe</a></p>
    </div>
  </div>
</body>
</html>`);
    setUploadError(null);
    setEditModalOpen(true);
  };

  const handleOpenEdit = (t: EmailTemplate) => {
    setEditingTemplate(t);
    setModalName(t.name);
    setModalSubject(t.subject);
    setModalCategory(t.category);
    setModalFolder(t.folder || "general");
    setModalImageUrl(t.imageUrl || "");
    setModalDescription(t.description || "");
    setModalHtml(t.htmlContent);
    setModalAttachments(t.attachments || []);
    setModalAttachmentError(null);
    setUploadError(null);
    setEditModalOpen(true);
  };

  const handleModalAttachmentChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    setModalAttachmentError(null);

    const maxFileSize = 4 * 1024 * 1024;
    const maxAttachments = 5;

    if (modalAttachments.length + files.length > maxAttachments) {
      setModalAttachmentError(`Maximum ${maxAttachments} attachments allowed per template.`);
      return;
    }

    const newAttachments: EmailAttachment[] = [];
    let filesProcessed = 0;
    const filesToProcess = Array.from(files);

    filesToProcess.forEach((file) => {
      if (file.size > maxFileSize) {
        setModalAttachmentError(`File "${file.name}" exceeds the 4MB limit.`);
        return;
      }

      const reader = new FileReader();
      reader.onload = (event) => {
        const result = event.target?.result as string;
        if (result) {
          const base64Data = result.split(",")[1];
          newAttachments.push({
            id: `att_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
            filename: file.name,
            contentType: file.type || "application/octet-stream",
            contentBase64: base64Data,
            size: file.size,
          });
        }
        filesProcessed++;
        if (filesProcessed === filesToProcess.length) {
          setModalAttachments((prev) => [...prev, ...newAttachments]);
        }
      };
      reader.onerror = () => {
        setModalAttachmentError(`Failed to read file "${file.name}".`);
      };
      reader.readAsDataURL(file);
    });

    e.target.value = "";
  };

  const removeModalAttachment = (idOrIndex: string | number) => {
    setModalAttachments((prev) =>
      prev.filter((item, idx) => (typeof idOrIndex === "string" ? item.id !== idOrIndex : idx !== idOrIndex))
    );
  };

  const handleImageFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploadingImage(true);
    setUploadError(null);

    try {
      if (!file.type.startsWith("image/")) {
        throw new Error(
          "Please choose an image file (PNG, JPG, WebP, GIF) for the template header. To attach PDF documents, use Attachments."
        );
      }
      if (file.size > 5 * 1024 * 1024) {
        throw new Error("Image file is too large (maximum 5MB).");
      }

      const formData = new FormData();
      formData.append("file", file);
      formData.append("folder", modalFolder || "general");

      const res = await apiFetch("/api/templates/images", {
        method: "POST",
        body: formData,
      });

      const text = await res.text();
      let data: any = {};
      try {
        data = text ? JSON.parse(text) : {};
      } catch {
        data = { error: text || `Upload failed with HTTP ${res.status}` };
      }

      if (!res.ok) {
        throw new Error(data.error || "Failed to upload image");
      }

      setModalImageUrl(data.image.url);
    } catch (err: any) {
      setUploadError(err.message || "Upload failed");
    } finally {
      setUploadingImage(false);
      e.target.value = "";
    }
  };

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

  const handleSaveTemplate = async (e: React.FormEvent) => {
    e.preventDefault();
    const toSave: EmailTemplate = {
      id: editingTemplate?.userId ? editingTemplate.id : `tpl_custom_${Date.now()}`,
      userId,
      name: modalName,
      subject: modalSubject,
      category: modalCategory,
      folder: modalFolder || "general",
      imageUrl: modalImageUrl || undefined,
      attachments: modalAttachments.length ? modalAttachments : undefined,
      description: modalDescription,
      htmlContent: modalHtml,
      createdAt: editingTemplate?.createdAt || new Date().toISOString(),
    };

    await saveTemplate(toSave);

    try {
      await apiFetch("/api/templates", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(toSave),
      });
    } catch (err) {
      console.warn("Template save sync notice:", err);
    }

    setEditModalOpen(false);
    await loadData();
  };

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

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to delete this template?")) return;
    await deleteTemplate(userId, id);
    await loadData();
  };

  const handleLibraryUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      alert("Please choose an image file (PNG, JPG, WebP, GIF).");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      alert("Image is too large (max 5MB).");
      return;
    }

    setUploadingLibraryImg(true);
    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("folder", uploadLibraryFolder || "general");

      const res = await apiFetch("/api/templates/images", {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        await loadLibraryImages(libraryFolderFilter);
      } else {
        const text = await res.text();
        let errData: any = {};
        try { errData = text ? JSON.parse(text) : {}; } catch {}
        alert(errData.error || `Upload failed (${res.status})`);
      }
    } catch (err: any) {
      console.error("Library upload error:", err);
      alert(err.message || "Failed to upload image.");
    } finally {
      setUploadingLibraryImg(false);
      e.target.value = "";
    }
  };

  const handleDeleteImage = async (imageId: string) => {
    if (!confirm("Are you sure you want to delete this asset?")) return;
    try {
      const res = await apiFetch(`/api/templates/images/${imageId}`, {
        method: "DELETE",
      });
      if (res.ok) {
        await loadLibraryImages(libraryFolderFilter);
      }
    } catch (err) {
      console.error("Delete asset error:", err);
    }
  };

  const allFolders = Array.from(
    new Set(["general", ...templates.map((t) => t.folder || "general")])
  ).filter(Boolean);

  const mediaFolders = Array.from(
    new Set([
      "general",
      ...templates.map((t) => t.folder || "general"),
      ...libraryImages.map((i) => i.folder || "general"),
    ])
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
          <h1 className="text-xl font-medium tracking-tight text-white">Email Templates & Assets</h1>
          <p className="text-xs text-zinc-400 font-mono mt-1">
            Modular HTML layouts, variable tokens, and organized template folders.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setImageLibraryOpen(true);
              loadLibraryImages("all");
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] hover:border-zinc-500 hover:text-white border border-[#262A2E] rounded-lg transition-colors"
          >
            <Folder className="w-3.5 h-3.5 text-zinc-400" />
            <span>Asset Folders</span>
          </button>

          <button
            onClick={handleOpenCreate}
            className="inline-flex items-center gap-2 px-4 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Custom Template</span>
          </button>
        </div>
      </div>

      {/* Filter Bar: Categories & Folders */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#111315] p-3 rounded-xl border border-[#262A2E]">
        {/* Category Filter Pills */}
        <div className="flex flex-wrap gap-1.5 text-xs font-mono">
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
              className={`px-3 py-1 rounded-lg text-xs transition-colors ${
                selectedCategory === cat.id
                  ? "bg-white text-black font-medium"
                  : "bg-[#171A1D] text-zinc-400 hover:text-zinc-200 border border-[#262A2E]"
              }`}
            >
              {cat.label}
            </button>
          ))}
        </div>

        {/* Folder Selector Dropdown */}
        {allFolders.length > 0 && (
          <div className="flex items-center gap-2 text-xs font-mono">
            <Folder className="w-3.5 h-3.5 text-zinc-500" />
            <select
              value={selectedFolder}
              onChange={(e) => setSelectedFolder(e.target.value)}
              className="px-2.5 py-1 text-xs bg-[#171A1D] border border-[#262A2E] text-zinc-300 rounded-lg focus:outline-none"
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
      {loading ? (
        <div className="p-12 text-center text-xs font-mono text-zinc-500">
          LOADING TEMPLATE REPOSITORY...
        </div>
      ) : filtered.length === 0 ? (
        <div className="p-12 text-center bg-[#111315] border border-[#262A2E] rounded-xl space-y-3">
          <FileCode2 className="w-10 h-10 text-zinc-600 mx-auto" />
          <h3 className="text-sm font-medium text-white">No templates found</h3>
          <p className="text-xs text-zinc-500 font-mono max-w-sm mx-auto">
            Click "New Custom Template" to craft your first branded email template.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {filtered.map((t) => (
            <div
              key={t.id}
              className="bg-[#111315] rounded-xl border border-[#262A2E] flex flex-col justify-between hover:border-zinc-500 transition-all overflow-hidden group"
            >
              {/* Optional Header Banner Image */}
              {t.imageUrl && (
                <div className="w-full h-36 bg-[#171A1D] relative overflow-hidden border-b border-[#262A2E]">
                  <img
                    src={t.imageUrl}
                    alt={t.name}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                  />
                </div>
              )}

              <div className="p-5 flex-1 flex flex-col justify-between space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-1.5">
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-[#171A1D] text-zinc-300 border border-[#262A2E]">
                        {t.category}
                      </span>
                      {t.folder && (
                        <span className="text-[10px] font-mono text-zinc-400 bg-[#171A1D] px-2 py-0.5 rounded border border-[#262A2E] flex items-center gap-1">
                          <Folder className="w-2.5 h-2.5 text-zinc-500" />
                          {t.folder}
                        </span>
                      )}
                      {t.attachments && t.attachments.length > 0 && (
                        <span className="text-[10px] font-mono text-zinc-300 bg-[#171A1D] px-2 py-0.5 rounded border border-[#262A2E] flex items-center gap-1">
                          <Paperclip className="w-2.5 h-2.5 text-zinc-400" />
                          <span>{t.attachments.length}</span>
                        </span>
                      )}
                    </div>
                  </div>

                  <h3 className="text-base font-medium text-white group-hover:text-zinc-200 transition-colors">
                    {t.name}
                  </h3>
                  <p className="text-xs text-zinc-400 mt-1 line-clamp-2">
                    {t.description || "Reusable responsive email template."}
                  </p>

                  <div className="mt-3 p-2.5 bg-[#171A1D] rounded-lg border border-[#262A2E] font-mono">
                    <span className="text-[10px] text-zinc-500 uppercase tracking-wider block">Subject:</span>
                    <span className="text-xs text-zinc-200 line-clamp-1 mt-0.5">
                      {t.subject}
                    </span>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="pt-3 border-t border-[#1C2024] flex items-center justify-between">
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => setPreviewTemplate(t)}
                      title="Preview Template"
                      className="p-1.5 text-zinc-400 hover:text-white hover:bg-[#171A1D] rounded-lg transition-colors"
                    >
                      <Eye className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => handleDuplicate(t)}
                      title="Duplicate Template"
                      className="p-1.5 text-zinc-400 hover:text-white hover:bg-[#171A1D] rounded-lg transition-colors"
                    >
                      <Copy className="w-4 h-4" />
                    </button>

                    <button
                      onClick={() => handleOpenEdit(t)}
                      title="Edit Template"
                      className="p-1.5 text-zinc-400 hover:text-white hover:bg-[#171A1D] rounded-lg transition-colors"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>

                    {t.userId && (
                      <button
                        onClick={() => handleDelete(t.id)}
                        title="Delete Template"
                        className="p-1.5 text-zinc-500 hover:text-red-400 hover:bg-[#171A1D] rounded-lg transition-colors"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>

                  <button
                    onClick={() => router.push(`/dashboard/compose?templateId=${t.id}`)}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-white bg-[#171A1D] hover:bg-[#1D2125] border border-[#262A2E] hover:border-zinc-500 rounded-lg transition-colors"
                  >
                    <Send className="w-3 h-3" />
                    <span>Use in Campaign</span>
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* EDIT / CREATE TEMPLATE MODAL */}
      {editModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-3xl w-full p-6 space-y-4 my-8">
            <div className="flex items-center justify-between pb-3 border-b border-[#262A2E]">
              <div>
                <h2 className="text-sm font-medium text-white">
                  {editingTemplate ? "Edit Email Template" : "Create New Custom Template"}
                </h2>
                <p className="text-xs text-zinc-400 font-mono mt-0.5">
                  Configure HTML body, folder category, and header banner.
                </p>
              </div>
              <button
                onClick={() => setEditModalOpen(false)}
                className="p-1 text-zinc-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSaveTemplate} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="sm:col-span-2">
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    Template Name
                  </label>
                  <input
                    type="text"
                    required
                    value={modalName}
                    onChange={(e) => setModalName(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                    placeholder="e.g. Q4 Customer Outreach"
                  />
                </div>
                <div>
                  <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                    Category
                  </label>
                  <select
                    value={modalCategory}
                    onChange={(e) => setModalCategory(e.target.value)}
                    className="w-full px-3 py-2 text-xs bg-[#171A1D] border border-[#262A2E] text-white font-mono rounded-lg focus:outline-none"
                  >
                    <option value="custom">Custom</option>
                    <option value="outreach">Cold Outreach</option>
                    <option value="event">Event / Webinar</option>
                    <option value="announcement">Product Announcement</option>
                    <option value="newsletter">Newsletter</option>
                  </select>
                </div>
              </div>

              {/* Folder & Optional Image Section */}
              <div className="p-4 bg-[#171A1D] rounded-xl border border-[#262A2E] space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] font-mono text-zinc-400 mb-1 flex items-center gap-1">
                      <Folder className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Template Folder</span>
                    </label>
                    <input
                      type="text"
                      value={modalFolder}
                      onChange={(e) => setModalFolder(e.target.value)}
                      placeholder="general, marketing, outreach"
                      className="w-full px-3 py-1.5 text-xs bg-[#111315] border border-[#262A2E] text-white rounded-lg font-mono focus:border-zinc-500 focus:outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-[11px] font-mono text-zinc-400 mb-1 flex items-center justify-between">
                      <span className="flex items-center gap-1">
                        <ImageIcon className="w-3.5 h-3.5 text-zinc-400" />
                        <span>Header Banner (Optional)</span>
                      </span>
                      <span className="text-[10px] font-mono text-zinc-500">
                        JPG, PNG, WebP
                      </span>
                    </label>

                    <div className="flex items-center gap-2">
                      <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono text-zinc-300 bg-[#111315] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors">
                        <UploadCloud className="w-3.5 h-3.5" />
                        <span>{uploadingImage ? "Uploading..." : "Upload Image"}</span>
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
                        placeholder="Image URL"
                        className="flex-1 px-3 py-1.5 text-xs bg-[#111315] border border-[#262A2E] text-white font-mono rounded-lg focus:border-zinc-500 focus:outline-none"
                      />
                    </div>

                    {uploadError && (
                      <p className="text-[11px] font-mono text-red-400 mt-1">{uploadError}</p>
                    )}
                  </div>
                </div>

                {/* Image Preview & HTML Insertion Helper */}
                {modalImageUrl && (
                  <div className="flex items-center justify-between p-2.5 bg-[#111315] border border-[#262A2E] rounded-lg">
                    <div className="flex items-center gap-3">
                      <img
                        src={modalImageUrl}
                        alt="Preview"
                        className="w-14 h-10 object-cover rounded border border-[#262A2E]"
                      />
                      <div>
                        <span className="text-[11px] font-medium text-white block">
                          Image active for template
                        </span>
                        <span className="text-[10px] text-zinc-500 font-mono truncate max-w-xs block">
                          {modalImageUrl}
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleInsertImageIntoHtml}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-mono text-zinc-300 bg-[#171A1D] hover:bg-[#1D2125] border border-[#262A2E] rounded transition-colors"
                      >
                        <Code2 className="w-3 h-3" />
                        <span>Insert HTML Tag</span>
                      </button>

                      <button
                        type="button"
                        onClick={() => setModalImageUrl("")}
                        className="text-zinc-500 hover:text-red-400 p-1"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                )}

                {/* Template Attachments (PDF & Documents) */}
                <div className="pt-2 border-t border-[#262A2E] space-y-2">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-1.5">
                      <Paperclip className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Default Attachments (PDF, Documents)</span>
                      {modalAttachments.length > 0 && (
                        <span className="text-[10px] bg-[#111315] text-zinc-300 px-1.5 py-0.5 rounded font-mono border border-[#262A2E]">
                          {modalAttachments.length}/5
                        </span>
                      )}
                    </label>
                    <label className="cursor-pointer inline-flex items-center gap-1 px-2.5 py-1 text-xs font-mono text-zinc-300 bg-[#111315] border border-[#262A2E] rounded-lg hover:border-zinc-500 hover:text-white transition-colors">
                      <UploadCloud className="w-3.5 h-3.5 text-zinc-400" />
                      <span>Attach File</span>
                      <input
                        type="file"
                        multiple
                        accept=".pdf,application/pdf,image/*,.doc,.docx,.txt,.csv"
                        onChange={handleModalAttachmentChange}
                        className="hidden"
                      />
                    </label>
                  </div>

                  {modalAttachmentError && (
                    <div className="flex items-center gap-1.5 text-red-400 text-xs bg-red-950/40 p-2 rounded-lg border border-red-500/30 font-mono">
                      <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                      <span>{modalAttachmentError}</span>
                    </div>
                  )}

                  {modalAttachments.length > 0 ? (
                    <div className="space-y-1.5">
                      {modalAttachments.map((file, fileIdx) => {
                        const isPdf = file.filename.toLowerCase().endsWith(".pdf") || file.contentType.includes("pdf");
                        const sizeFormatted = file.size < 1024 * 1024
                          ? `${(file.size / 1024).toFixed(1)} KB`
                          : `${(file.size / (1024 * 1024)).toFixed(2)} MB`;
                        return (
                          <div
                            key={file.id || fileIdx}
                            className="flex items-center justify-between p-2 rounded-lg border border-[#262A2E] bg-[#111315]"
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <div className="p-1 rounded bg-[#171A1D] text-zinc-400">
                                <FileText className="w-3.5 h-3.5" />
                              </div>
                              <div className="truncate">
                                <span className="text-xs font-medium text-white block truncate">
                                  {file.filename}
                                </span>
                                <span className="text-[10px] text-zinc-500 font-mono">
                                  {isPdf ? "PDF Document" : file.contentType} · {sizeFormatted}
                                </span>
                              </div>
                            </div>
                            <button
                              type="button"
                              onClick={() => removeModalAttachment(file.id || fileIdx)}
                              className="p-1 text-zinc-500 hover:text-red-400 rounded transition-colors"
                              title="Remove attachment"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        );
                      })}
                    </div>
                  ) : null}
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  Default Subject Line
                </label>
                <input
                  type="text"
                  required
                  value={modalSubject}
                  onChange={(e) => setModalSubject(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                  placeholder="Subject line with {{firstName}}"
                />
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">
                  Description
                </label>
                <input
                  type="text"
                  value={modalDescription}
                  onChange={(e) => setModalDescription(e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-[#171A1D] border border-[#262A2E] text-white rounded-lg focus:border-zinc-500 focus:outline-none"
                  placeholder="Description of template purpose"
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-[11px] font-mono text-zinc-400">
                    HTML Template Code
                  </label>
                  <span className="text-[11px] text-zinc-500 font-mono">
                    Tokens: {"{{firstName}}"}, {"{{company}}"}, {"{{fromName}}"}
                  </span>
                </div>
                <textarea
                  rows={9}
                  required
                  value={modalHtml}
                  onChange={(e) => setModalHtml(e.target.value)}
                  className="w-full p-2.5 font-mono text-xs bg-[#171A1D] border border-[#262A2E] text-zinc-200 rounded-lg focus:border-zinc-500 focus:outline-none"
                />
              </div>

              <div className="flex items-center justify-end gap-2 pt-3 border-t border-[#262A2E]">
                <button
                  type="button"
                  onClick={() => setEditModalOpen(false)}
                  className="px-4 py-2 text-xs font-mono text-zinc-400 hover:text-white rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors"
                >
                  Save Template
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ASSET FOLDERS & MEDIA LIBRARY MODAL */}
      {imageLibraryOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-3xl w-full p-6 space-y-4 my-8">
            <div className="flex items-center justify-between pb-3 border-b border-[#262A2E]">
              <div>
                <div className="flex items-center gap-2">
                  <Folder className="w-4 h-4 text-zinc-300" />
                  <h2 className="text-sm font-medium text-white">
                    Asset Folders & Media Library
                  </h2>
                </div>
                <p className="text-xs text-zinc-400 font-mono mt-0.5">
                  Personal media files organized into your custom folders.
                </p>
              </div>
              <button
                onClick={() => setImageLibraryOpen(false)}
                className="p-1 text-zinc-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Upload image to specific folder */}
            <div className="p-3.5 bg-[#171A1D] border border-[#262A2E] rounded-xl flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2 font-mono">
                <Folder className="w-4 h-4 text-zinc-400" />
                <span className="text-zinc-400">Target Folder:</span>
                <input
                  type="text"
                  value={uploadLibraryFolder}
                  onChange={(e) => setUploadLibraryFolder(e.target.value)}
                  placeholder="general, marketing..."
                  className="px-2.5 py-1 text-xs bg-[#111315] border border-[#262A2E] text-white rounded w-40 font-mono focus:outline-none"
                />
              </div>

              <label className="cursor-pointer inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors">
                <UploadCloud className="w-3.5 h-3.5" />
                <span>{uploadingLibraryImg ? "Uploading..." : "Upload to Folder"}</span>
                <input
                  type="file"
                  accept="image/*"
                  onChange={handleLibraryUpload}
                  disabled={uploadingLibraryImg}
                  className="hidden"
                />
              </label>
            </div>

            {/* Filter images by folder - user's own folders */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-zinc-500">Folder filter:</span>
              {["all", ...mediaFolders].map((f) => (
                <button
                  key={f}
                  onClick={() => {
                    setLibraryFolderFilter(f);
                    loadLibraryImages(f);
                  }}
                  className={`px-2.5 py-1 rounded text-xs transition-colors ${
                    libraryFolderFilter === f
                      ? "bg-white text-black font-medium"
                      : "bg-[#171A1D] text-zinc-400 hover:text-zinc-200 border border-[#262A2E]"
                  }`}
                >
                  {f === "all" ? "All Folders" : f}
                </button>
              ))}
            </div>

            {/* Images Grid */}
            {loadingImages ? (
              <div className="py-12 text-center text-xs font-mono text-zinc-500">
                LOADING ASSETS...
              </div>
            ) : libraryImages.length === 0 ? (
              <div className="py-12 text-center text-xs font-mono text-zinc-500 border border-dashed border-[#262A2E] rounded-xl space-y-2">
                <ImageIcon className="w-8 h-8 text-zinc-600 mx-auto" />
                <p>No assets found in this folder.</p>
              </div>
            ) : (
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 max-h-96 overflow-y-auto p-1">
                {libraryImages.map((img) => (
                  <div
                    key={img.id}
                    className="border border-[#262A2E] rounded-xl overflow-hidden bg-[#171A1D] group flex flex-col justify-between"
                  >
                    <div className="h-28 bg-[#111315] relative overflow-hidden">
                      <img
                        src={img.url}
                        alt={img.filename}
                        className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                      />
                      <span className="absolute bottom-1 left-1 bg-black/80 border border-[#262A2E] text-zinc-300 text-[9px] px-1.5 py-0.5 rounded font-mono">
                        📁 {img.folder || "general"}
                      </span>
                    </div>

                    <div className="p-2.5 text-xs space-y-2 font-mono">
                      <p className="text-white truncate" title={img.filename}>
                        {img.filename}
                      </p>

                      <div className="flex items-center justify-between pt-1 border-t border-[#262A2E]">
                        <button
                          type="button"
                          onClick={() => {
                            navigator.clipboard.writeText(img.url);
                            setCopiedUrl(img.id);
                            setTimeout(() => setCopiedUrl(null), 2000);
                          }}
                          className="inline-flex items-center gap-1 text-[11px] text-zinc-300 hover:text-white"
                        >
                          {copiedUrl === img.id ? (
                            <Check className="w-3 h-3 text-emerald-400" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                          <span>{copiedUrl === img.id ? "Copied" : "Copy URL"}</span>
                        </button>

                        <button
                          type="button"
                          onClick={() => handleDeleteImage(img.id)}
                          className="text-zinc-500 hover:text-red-400 p-1"
                          title="Delete asset"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-[#262A2E]">
              <button
                type="button"
                onClick={() => setImageLibraryOpen(false)}
                className="px-4 py-2 text-xs font-mono text-zinc-400 hover:text-white rounded-lg"
              >
                Close Library
              </button>
            </div>
          </div>
        </div>
      )}

      {/* PREVIEW TEMPLATE MODAL */}
      {previewTemplate && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#111315] rounded-xl border border-[#262A2E] max-w-2xl w-full p-6 space-y-4 max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-[#262A2E]">
              <div>
                <h2 className="text-sm font-medium text-white">{previewTemplate.name}</h2>
                <p className="text-xs text-zinc-400 font-mono mt-0.5">{previewTemplate.subject}</p>
              </div>
              <button
                onClick={() => setPreviewTemplate(null)}
                className="p-1 text-zinc-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto border border-[#262A2E] rounded-xl p-4 bg-[#08090A]">
              <iframe
                title="Preview"
                srcDoc={previewTemplate.htmlContent}
                className="w-full min-h-[380px] bg-white rounded-lg border border-zinc-700"
              />
            </div>

            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-zinc-500 font-mono">
                Created: {formatDate(previewTemplate.createdAt)}
              </span>
              <button
                onClick={() => {
                  router.push(`/dashboard/compose?templateId=${previewTemplate.id}`);
                  setPreviewTemplate(null);
                }}
                className="inline-flex items-center gap-1.5 px-4 py-2 text-xs font-medium text-black bg-white hover:bg-zinc-200 rounded-lg transition-colors"
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
