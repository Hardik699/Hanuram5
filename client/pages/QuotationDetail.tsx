import { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Edit2,
  Trash2,
  FileText,
  MoreVertical,
  ArrowLeft,
  Check,
  AlertCircle,
} from "lucide-react";
import { Layout } from "@/components/Layout";
import Modal from "@/components/ui/Modal";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

interface RecipeItem {
  _id?: string;
  rawMaterialId: string;
  rawMaterialName: string;
  rawMaterialCode: string;
  quantity: number;
  unitId?: string;
  unitName?: string;
  price: number;
  vendorId?: string;
  vendorName?: string;
  totalPrice: number;
}

interface Quotation {
  _id: string;
  recipeId: string;
  recipeName?: string;
  companyName: string;
  reason: string;
  quantity: number;
  unitId: string;
  unitName?: string;
  date: string;
  createdBy: string;
  phoneNumber: string;
  email: string;
  items: RecipeItem[];
  createdAt: string;
  updatedAt: string;
}

interface QuotationLog {
  _id: string;
  quotationId: string;
  action: string;
  details: string;
  createdAt: string;
  changedBy: string;
}

export default function QuotationDetail() {
  const { quotationId } = useParams();
  const navigate = useNavigate();

  // Data
  const [quotation, setQuotation] = useState<Quotation | null>(null);
  const [logs, setLogs] = useState<QuotationLog[]>([]);

  // UI State
  const [loading, setLoading] = useState(true);
  const [showLogsModal, setShowLogsModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteError, setDeleteError] = useState("");
  const [isEditing, setIsEditing] = useState(false);

  // Edit Form
  const [editForm, setEditForm] = useState({
    companyName: "",
    reason: "",
    quantity: "",
    date: "",
    phoneNumber: "",
    email: "",
  });

  useEffect(() => {
    const token = localStorage.getItem("auth_token");
    if (!token) {
      navigate("/");
      return;
    }
    fetchAllData();
  }, [quotationId]);

  const fetchAllData = async () => {
    try {
      setLoading(true);
      if (quotationId) {
        await Promise.all([fetchQuotation(), fetchLogs()]);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      toast.error("Failed to load quotation");
    } finally {
      setLoading(false);
    }
  };

  const fetchQuotation = async () => {
    try {
      if (quotationId) {
        const response = await fetch(`/api/quotations/${quotationId}`);
        const data = await response.json();
        if (data.success) {
          setQuotation(data.data);
          setEditForm({
            companyName: data.data.companyName,
            reason: data.data.reason,
            quantity: data.data.quantity,
            date: data.data.date,
            phoneNumber: data.data.phoneNumber,
            email: data.data.email,
          });
        }
      }
    } catch (error) {
      console.error("Error fetching quotation:", error);
    }
  };

  const fetchLogs = async () => {
    try {
      if (quotationId) {
        const response = await fetch(`/api/quotations/${quotationId}/logs`);
        const data = await response.json();
        if (data.success) setLogs(data.data);
      }
    } catch (error) {
      console.error("Error fetching logs:", error);
    }
  };

  const handleUpdateQuotation = async () => {
    if (!quotation) return;

    try {
      const response = await fetch(`/api/quotations/${quotationId}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...editForm,
          quantity: Number(editForm.quantity),
          unitId: quotation.unitId,
          items: quotation.items,
          createdBy: localStorage.getItem("username") || "System",
        }),
      });

      const data = await response.json();
      if (data.success) {
        toast.success("Quotation updated successfully");
        setIsEditing(false);
        fetchQuotation();
      } else {
        toast.error(data.message || "Failed to update quotation");
      }
    } catch (error) {
      toast.error("Failed to update quotation");
    }
  };

  const handleDeleteQuotation = async () => {
    if (!deletePassword) {
      setDeleteError("Password is required");
      return;
    }

    try {
      const response = await fetch(`/api/quotations/${quotationId}`, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          password: deletePassword,
          deletedBy: localStorage.getItem("username") || "System",
        }),
      });

      const data = await response.json();
      if (data.success) {
        toast.success("Quotation deleted successfully");
        navigate(`/recipe/${quotation?.recipeId}`);
      } else {
        setDeleteError(data.message || "Failed to delete");
      }
    } catch (error) {
      setDeleteError("Failed to delete quotation");
    }
  };

  const handlePrintQuotationPDF = () => {
    if (!quotation) return;
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      const totalCost = quotation.items?.reduce((sum, item) => sum + (item.totalPrice ?? item.calculatedTotal ?? 0), 0) || 0;
      const today = new Date().toLocaleDateString("en-IN", { day: "2-digit", month: "long", year: "numeric" });
      const quotationDate = new Date(quotation.date).toLocaleDateString("en-GB");

      const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Quotation - ${quotation.companyName}</title>
          <meta charset="UTF-8">
          <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: 'Segoe UI', Arial, sans-serif; background: #fff; color: #1a1a2e; font-size: 13px; }

            .header {
              background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
              color: white;
              padding: 28px 40px 22px;
              display: flex;
              justify-content: space-between;
              align-items: center;
            }
            .company-name { font-size: 26px; font-weight: 800; letter-spacing: 1px; }
            .company-sub { font-size: 11px; opacity: 0.8; margin-top: 3px; letter-spacing: 2px; text-transform: uppercase; }
            .doc-info { text-align: right; }
            .doc-title { font-size: 14px; font-weight: 700; background: rgba(255,255,255,0.2); padding: 6px 14px; border-radius: 20px; display: inline-block; }
            .doc-date { font-size: 11px; opacity: 0.75; margin-top: 6px; }

            .title-band {
              background: #f0f6ff;
              border-left: 6px solid #2563eb;
              padding: 18px 40px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              border-bottom: 1px solid #dbeafe;
            }
            .client-name { font-size: 22px; font-weight: 800; color: #1e3a5f; text-transform: uppercase; }
            .reason-badge { background: #2563eb; color: white; padding: 5px 16px; border-radius: 20px; font-size: 12px; font-weight: 700; }

            .info-section { padding: 20px 40px; border-bottom: 1px solid #e5e7eb; }
            .section-title {
              font-size: 11px; font-weight: 700; color: #6b7280;
              text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 14px;
              display: flex; align-items: center; gap: 8px;
            }
            .section-title::after { content: ''; flex: 1; height: 1px; background: #e5e7eb; }
            .info-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
            .info-card { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; }
            .info-label { font-size: 10px; color: #9ca3af; font-weight: 600; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 4px; }
            .info-value { font-size: 15px; font-weight: 700; color: #111827; }
            .info-value.green { color: #059669; }
            .info-value.blue { color: #2563eb; }

            .table-section { padding: 20px 40px; }
            table { width: 100%; border-collapse: collapse; }
            thead tr { background: linear-gradient(135deg, #1e3a5f, #2563eb); color: white; }
            thead th { padding: 11px 14px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; }
            thead th:first-child { border-radius: 6px 0 0 6px; }
            thead th:last-child { border-radius: 0 6px 6px 0; }
            tbody tr { border-bottom: 1px solid #f3f4f6; }
            tbody tr:nth-child(even) { background: #f9fafb; }
            tbody td { padding: 10px 14px; font-size: 12px; color: #374151; }
            .rm-name { font-weight: 600; color: #111827; }
            .rm-code { font-size: 10px; color: #9ca3af; margin-top: 2px; }
            .text-right { text-align: right; }
            .text-center { text-align: center; }
            .price-cell { font-weight: 600; }
            .total-cell { font-weight: 700; color: #1e3a5f; }

            .summary-bar {
              margin: 0 40px 20px;
              background: linear-gradient(135deg, #1e3a5f, #2563eb);
              border-radius: 10px; padding: 18px 28px;
              display: flex; justify-content: flex-end; gap: 50px; color: white;
            }
            .summary-item { text-align: center; }
            .summary-label { font-size: 10px; opacity: 0.8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 4px; }
            .summary-value { font-size: 20px; font-weight: 800; }

            .footer {
              background: #f9fafb; border-top: 2px solid #e5e7eb;
              padding: 14px 40px; display: flex; justify-content: space-between;
              align-items: center; font-size: 10px; color: #9ca3af;
            }
            .footer-brand { font-weight: 700; color: #6b7280; font-size: 11px; }

            @media print {
              body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
              @page { margin: 0; size: A4; }
            }
          </style>
        </head>
        <body>
          <div class="header">
            <div>
              <div class="company-name">🍬 HANURAM FOODS</div>
              <div class="company-sub">Premium Quality · Authentic Taste</div>
            </div>
            <div class="doc-info">
              <div class="doc-title">📄 QUOTATION</div>
              <div class="doc-date">Generated: ${today}</div>
            </div>
          </div>

          <div class="title-band">
            <div>
              <div style="font-size:11px;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">Client</div>
              <div class="client-name">${quotation.companyName}</div>
            </div>
            <div class="reason-badge">${quotation.reason}</div>
          </div>

          <div class="info-section">
            <div class="section-title">Quotation Details</div>
            <div class="info-grid">
              <div class="info-card">
                <div class="info-label">Quotation Date</div>
                <div class="info-value">${quotationDate}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Required Qty</div>
                <div class="info-value blue">${quotation.requiredQty ?? quotation.quantity ?? "—"} ${quotation.unitName || ""}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Phone</div>
                <div class="info-value">${quotation.phoneNumber || "—"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Email</div>
                <div class="info-value" style="font-size:12px;">${quotation.email || "—"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Prepared By</div>
                <div class="info-value">${quotation.createdBy || "admin"}</div>
              </div>
              <div class="info-card">
                <div class="info-label">Total Items</div>
                <div class="info-value">${quotation.items?.length || 0} Materials</div>
              </div>
              <div class="info-card">
                <div class="info-label">Total Cost</div>
                <div class="info-value green">₹${totalCost.toLocaleString("en-IN", { minimumFractionDigits: 2 })}</div>
              </div>
              ${quotation.perUnitCost ? `
              <div class="info-card">
                <div class="info-label">Per Unit Cost</div>
                <div class="info-value green">₹${Number(quotation.perUnitCost).toFixed(2)}</div>
              </div>` : '<div class="info-card"><div class="info-label">Scaling Factor</div><div class="info-value">${quotation.scalingFactor ?? "—"}x</div></div>'}
            </div>
          </div>

          <div class="table-section">
            <div class="section-title">Raw Materials Required</div>
            <table>
              <thead>
                <tr>
                  <th style="width:38%">Raw Material</th>
                  <th class="text-center" style="width:12%">Master Qty</th>
                  <th class="text-center" style="width:12%">Required Qty</th>
                  <th class="text-center" style="width:8%">Unit</th>
                  <th class="text-right" style="width:15%">Unit Price</th>
                  <th class="text-right" style="width:15%">Total</th>
                </tr>
              </thead>
              <tbody>
                ${quotation.items?.map((item) => {
                  const qty = item.calculatedQty ?? item.quantity ?? 0;
                  const price = item.unitPrice ?? item.price ?? 0;
                  const total = item.calculatedTotal ?? item.totalPrice ?? (qty * price);
                  return `
                  <tr>
                    <td>
                      <div class="rm-name">${item.rawMaterialName || "—"}</div>
                      <div class="rm-code">${item.rawMaterialCode || ""}</div>
                    </td>
                    <td class="text-center">${item.masterQty ?? "—"}</td>
                    <td class="text-center">${Number(qty).toFixed(3)}</td>
                    <td class="text-center">${item.unitName || "—"}</td>
                    <td class="text-right price-cell">₹${Number(price).toFixed(2)}</td>
                    <td class="text-right total-cell">₹${Number(total).toFixed(2)}</td>
                  </tr>`;
                }).join("")}
              </tbody>
            </table>
          </div>

          <div class="summary-bar">
            <div class="summary-item">
              <div class="summary-label">Total RM Cost</div>
              <div class="summary-value">₹${totalCost.toLocaleString("en-IN", { minimumFractionDigits: 2 })}</div>
            </div>
            ${quotation.perUnitCost ? `
            <div class="summary-item">
              <div class="summary-label">Per Unit Cost</div>
              <div class="summary-value">₹${Number(quotation.perUnitCost).toFixed(2)}</div>
            </div>` : ""}
          </div>

          <div class="footer">
            <div class="footer-brand">🍬 HANURAM FOODS — Confidential Quotation Document</div>
            <div>${quotation.companyName} · ${quotationDate}</div>
          </div>

          <script>window.onload = () => { window.print(); }</script>
        </body>
        </html>
      `;
      printWindow.document.write(htmlContent);
      printWindow.document.close();
    }
  };

  if (loading) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-screen">
          <p>Loading...</p>
        </div>
      </Layout>
    );
  }

  if (!quotation) {
    return (
      <Layout>
        <div className="flex items-center justify-center min-h-screen">
          <p>Quotation not found</p>
        </div>
      </Layout>
    );
  }

  const totalCost = quotation.items?.reduce((sum, item) => sum + item.totalPrice, 0) || 0;

  return (
    <Layout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate(`/recipe/${quotation.recipeId}`)}
              className="p-2 hover:bg-secondary rounded-lg transition"
            >
              <ArrowLeft size={20} />
            </button>
            <div>
              <p className="text-sm text-muted-foreground">Quotation</p>
              <h1 className="text-3xl font-bold">{quotation.companyName}</h1>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setIsEditing(!isEditing)}
              className="p-2 hover:bg-secondary rounded-lg transition"
            >
              <Edit2 size={20} />
            </button>
            <button
              onClick={() => setShowDeleteModal(true)}
              className="p-2 hover:bg-destructive/10 text-destructive rounded-lg transition"
            >
              <Trash2 size={20} />
            </button>
            <button
              onClick={() => setShowLogsModal(true)}
              className="p-2 hover:bg-secondary rounded-lg transition"
            >
              <MoreVertical size={20} />
            </button>
          </div>
        </div>

        {/* Edit Mode */}
        {isEditing ? (
          <div className="bg-card rounded-lg p-6 border space-y-4">
            <h2 className="text-xl font-semibold">Edit Quotation</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium">Company Name *</label>
                <input
                  type="text"
                  value={editForm.companyName}
                  onChange={(e) =>
                    setEditForm({ ...editForm, companyName: e.target.value })
                  }
                  className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Reason *</label>
                <input
                  type="text"
                  value={editForm.reason}
                  onChange={(e) =>
                    setEditForm({ ...editForm, reason: e.target.value })
                  }
                  className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Quantity *</label>
                <input
                  type="number"
                  value={editForm.quantity}
                  onChange={(e) =>
                    setEditForm({ ...editForm, quantity: e.target.value })
                  }
                  className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Date *</label>
                <input
                  type="date"
                  value={editForm.date}
                  onChange={(e) =>
                    setEditForm({ ...editForm, date: e.target.value })
                  }
                  className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Phone Number *</label>
                <input
                  type="tel"
                  value={editForm.phoneNumber}
                  onChange={(e) =>
                    setEditForm({ ...editForm, phoneNumber: e.target.value })
                  }
                  className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                />
              </div>
              <div>
                <label className="text-sm font-medium">Email *</label>
                <input
                  type="email"
                  value={editForm.email}
                  onChange={(e) =>
                    setEditForm({ ...editForm, email: e.target.value })
                  }
                  className="w-full mt-1 px-3 py-2 border rounded-md bg-input"
                />
              </div>
            </div>

            <div className="flex gap-2 pt-4">
              <Button onClick={handleUpdateQuotation} variant="default" size="sm">
                Save Changes
              </Button>
              <Button
                onClick={() => setIsEditing(false)}
                variant="outline"
                size="sm"
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : (
          /* View Mode */
          <div className="bg-card rounded-lg p-6 border">
            <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
              <div>
                <p className="text-sm text-muted-foreground">Company Name</p>
                <p className="font-semibold">{quotation.companyName}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Reason</p>
                <p className="font-semibold">{quotation.reason}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Quantity</p>
                <p className="font-semibold">{quotation.quantity}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Date</p>
                <p className="font-semibold">
                  {new Date(quotation.date).toLocaleDateString("en-GB")}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Created By</p>
                <p className="font-semibold">{quotation.createdBy}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Phone</p>
                <p className="font-semibold">{quotation.phoneNumber}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Email</p>
                <p className="font-semibold">{quotation.email}</p>
              </div>
            </div>
          </div>
        )}

        {/* Items Table */}
        <div className="bg-card rounded-lg p-6 border">
          <h2 className="text-xl font-semibold mb-4">Quotation Items</h2>
          <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-700">
            <table className="w-full">
              <thead className="bg-slate-100 dark:bg-slate-700 border-b border-slate-200 dark:border-slate-600">
                <tr>
                  <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">Raw Material</th>
                  <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">Qty</th>
                  <th className="text-left py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">Unit</th>
                  <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">Unit Price</th>
                  <th className="text-right py-3 px-4 font-semibold text-slate-900 dark:text-white text-sm">Total</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                {quotation.items?.map((item, idx) => (
                  <tr key={idx} className="hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                    <td className="py-4 px-4">
                      <p className="font-medium text-slate-900 dark:text-white">{item.rawMaterialName}</p>
                      <p className="text-xs text-slate-600 dark:text-slate-400 mt-1">{item.rawMaterialCode}</p>
                    </td>
                    <td className="py-4 px-4 text-slate-700 dark:text-slate-300 font-medium">{item.quantity}</td>
                    <td className="py-4 px-4 text-slate-700 dark:text-slate-300">{item.unitName || "-"}</td>
                    <td className="py-4 px-4 text-right text-slate-900 dark:text-white font-medium">₹{item.price.toFixed(2)}</td>
                    <td className="py-4 px-4 text-right font-semibold text-teal-600 dark:text-teal-400">
                      ₹{item.totalPrice.toFixed(2)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Summary */}
          <div className="flex justify-end mt-6 pt-6 border-t border-slate-200 dark:border-slate-700">
            <div className="text-right">
              <p className="text-sm text-slate-600 dark:text-slate-400 mb-1">Total Cost</p>
              <p className="text-xl font-bold text-green-600 dark:text-green-400">₹{totalCost.toFixed(2)}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Logs Modal */}
      {showLogsModal && (
        <Modal onClose={() => setShowLogsModal(false)}>
          <div className="bg-card rounded-lg p-6 max-w-2xl max-h-96 overflow-y-auto">
            <h2 className="text-xl font-semibold mb-4">Quotation Logs</h2>
            {logs.length === 0 ? (
              <p className="text-muted-foreground">No logs found</p>
            ) : (
              <div className="space-y-3">
                {logs.map((log) => (
                  <div key={log._id} className="border rounded-lg p-3 text-sm">
                    <p className="font-semibold">{log.action.toUpperCase()}</p>
                    <p className="text-muted-foreground">{log.details}</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(log.createdAt).toLocaleString()} by {log.changedBy}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Modal>
      )}

      {/* Delete Modal */}
      {showDeleteModal && (
        <Modal onClose={() => setShowDeleteModal(false)}>
          <div className="bg-card rounded-lg p-6 max-w-sm">
            <h2 className="text-xl font-semibold mb-4">Delete Quotation</h2>
            <p className="text-muted-foreground mb-4">
              This action cannot be undone. Please enter your password to confirm.
            </p>
            <input
              type="password"
              value={deletePassword}
              onChange={(e) => {
                setDeletePassword(e.target.value);
                setDeleteError("");
              }}
              placeholder="Enter password"
              className="w-full px-3 py-2 border rounded-md bg-input mb-2"
            />
            {deleteError && (
              <p className="text-destructive text-sm mb-4">{deleteError}</p>
            )}
            <div className="flex gap-2">
              <Button
                onClick={handleDeleteQuotation}
                variant="destructive"
                className="flex-1"
              >
                Delete
              </Button>
              <Button
                onClick={() => {
                  setShowDeleteModal(false);
                  setDeletePassword("");
                  setDeleteError("");
                }}
                variant="outline"
                className="flex-1"
              >
                Cancel
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </Layout>
  );
}



