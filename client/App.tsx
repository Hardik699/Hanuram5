import "./global.css";

import { Suspense, lazy } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { AuthProvider } from "@/context/AuthContext";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import ProtectedRoute from "./components/ProtectedRoute";

// Lazy load all page components for code-splitting
const Login = lazy(() => import("./pages/Login"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const CreateCategory = lazy(() => import("./pages/CreateCategory"));
const CategoryDetail = lazy(() => import("./pages/CategoryDetail"));
const CreateSubCategory = lazy(() => import("./pages/CreateSubCategory"));
const SubCategoryDetail = lazy(() => import("./pages/SubCategoryDetail"));
const CreateUnit = lazy(() => import("./pages/CreateUnit"));
const UnitDetail = lazy(() => import("./pages/UnitDetail"));
const CreateVendor = lazy(() => import("./pages/CreateVendor"));
const VendorDetail = lazy(() => import("./pages/VendorDetail"));
const CreateRawMaterial = lazy(() => import("./pages/CreateRawMaterial"));
const CreateRecipe = lazy(() => import("./pages/CreateRecipe"));
const RMManagement = lazy(() => import("./pages/RMManagement"));
const RMDetail = lazy(() => import("./pages/RMDetail"));
const RMCManagement = lazy(() => import("./pages/RMCManagement"));
const RecipeDetail = lazy(() => import("./pages/RecipeDetail"));
const QuotationDetail = lazy(() => import("./pages/QuotationDetail"));
const NotFound = lazy(() => import("./pages/NotFound"));
const LabourManagement = lazy(() => import("./pages/LabourManagement"));
const CreateLabour = lazy(() => import("./pages/CreateLabour"));
const CostingAnalysis = lazy(() => import("./pages/CostingAnalysis"));
const OpCostManagement = lazy(() => import("./pages/OpCostManagement"));

// Loading fallback component
const PageLoader = () => (
  <LoadingSpinner message="Loading page..." fullScreen={true} />
);

const queryClient = new QueryClient();

const App = () => (
  <AuthProvider>
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Suspense fallback={<PageLoader />}>
            <Routes>
              <Route path="/" element={<Login />} />
              <Route
                path="/dashboard"
              element={
                <ProtectedRoute requiredPermission="dashboard_view">
                  <Dashboard />
                </ProtectedRoute>
              }
              />
              <Route
                path="/create-category"
              element={
                <ProtectedRoute requiredPermission="category_add">
                  <CreateCategory />
                </ProtectedRoute>
              }
              />
              <Route
              path="/category/:id"
              element={
                <ProtectedRoute requiredPermission="category_view">
                  <CategoryDetail />
                </ProtectedRoute>
              }
              />
              <Route
              path="/create-subcategory"
              element={
                <ProtectedRoute requiredPermission="subcategory_add">
                  <CreateSubCategory />
                </ProtectedRoute>
              }
              />
              <Route
              path="/subcategory/:id"
              element={
                <ProtectedRoute requiredPermission="subcategory_view">
                  <SubCategoryDetail />
                </ProtectedRoute>
              }
              />
              <Route
              path="/create-unit"
              element={
                <ProtectedRoute requiredPermission="unit_add">
                  <CreateUnit />
                </ProtectedRoute>
              }
              />
              <Route
              path="/unit/:id"
              element={
                <ProtectedRoute requiredPermission="unit_view">
                  <UnitDetail />
                </ProtectedRoute>
              }
              />
              <Route
              path="/create-vendor"
              element={
                <ProtectedRoute requiredPermission="vendor_add">
                  <CreateVendor />
                </ProtectedRoute>
              }
              />
              <Route
              path="/vendor/:id"
              element={
                <ProtectedRoute requiredPermission="vendor_view">
                  <VendorDetail />
                </ProtectedRoute>
              }
              />
              <Route
              path="/raw-materials"
              element={
                <ProtectedRoute requiredPermission="rm_view">
                  <RMManagement />
                </ProtectedRoute>
              }
              />
              <Route
              path="/raw-materials/new"
              element={
                <ProtectedRoute requiredPermission="rm_add">
                  <CreateRawMaterial />
                </ProtectedRoute>
              }
              />
              <Route
              path="/raw-materials/:id"
              element={
                <ProtectedRoute requiredPermission="rm_view">
                  <RMDetail />
                </ProtectedRoute>
              }
              />
              <Route
              path="/raw-materials/:id/edit"
              element={
                <ProtectedRoute requiredPermission="rm_edit">
                  <CreateRawMaterial />
                </ProtectedRoute>
              }
              />
              <Route
              path="/rmc"
              element={
                <ProtectedRoute requiredPermission="recipe_view">
                  <RMCManagement />
                </ProtectedRoute>
              }
              />
              <Route
              path="/recipe/new"
              element={
                <ProtectedRoute requiredPermission="recipe_add">
                  <CreateRecipe />
                </ProtectedRoute>
              }
              />
              <Route
              path="/recipe/:id/edit"
              element={
                <ProtectedRoute requiredPermission="recipe_edit">
                  <CreateRecipe />
                </ProtectedRoute>
              }
              />
              <Route
              path="/recipe/:recipeId"
              element={
                <ProtectedRoute requiredPermission="recipe_view">
                  <RecipeDetail />
                </ProtectedRoute>
              }
              />
              <Route
              path="/quotation/:quotationId"
              element={
                <ProtectedRoute requiredPermission="quotation_view">
                  <QuotationDetail />
                </ProtectedRoute>
              }
              />
              <Route
              path="/labour"
              element={
                <ProtectedRoute requiredPermission="labour_view">
                  <LabourManagement />
                </ProtectedRoute>
              }
              />
              <Route
              path="/labour/new"
              element={
                <ProtectedRoute requiredPermission="labour_add">
                  <CreateLabour />
                </ProtectedRoute>
              }
              />
              <Route
              path="/labour/:id/edit"
              element={
                <ProtectedRoute requiredPermission="labour_edit">
                  <CreateLabour />
                </ProtectedRoute>
              }
              />
              <Route
              path="/costing-calculator"
              element={
                <ProtectedRoute requiredPermission="recipe_view">
                  <CostingAnalysis />
                </ProtectedRoute>
              }
              />
              <Route
              path="/op-cost"
              element={
                <ProtectedRoute requiredPermission="opcost_view">
                  <OpCostManagement />
                </ProtectedRoute>
              }
            />
              {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
              <Route path="*" element={<NotFound />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </TooltipProvider>
    </QueryClientProvider>
  </AuthProvider>
);

export default App;
