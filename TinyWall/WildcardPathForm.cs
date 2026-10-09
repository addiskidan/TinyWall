using System;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace pylorak.TinyWall
{
    internal sealed class WildcardPathForm : Form
    {
        private readonly TextBox PatternBox;
        private readonly CheckBox Recursive;
        public string Pattern => PatternBox.Text;

        internal WildcardPathForm(string initialPattern)
        {
            Text = "Wildcard executable path";
            Icon = Resources.Icons.firewall;
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(600, 155);
            MinimumSize = new Size(450, 194);
            MaximumSize = new Size(1200, 194);
            StartPosition = FormStartPosition.CenterParent;
            ShowInTaskbar = false;
            MinimizeBox = false;
            MaximizeBox = false;

            var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(12), ColumnCount = 2, RowCount = 3 };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 45));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            PatternBox = new TextBox { Text = initialPattern, Dock = DockStyle.Fill, AccessibleName = "Executable path pattern" };
            var browse = new Button { Text = "Folder...", Dock = DockStyle.Fill };
            browse.Click += Browse_Click;
            Recursive = new CheckBox { Text = "Include subfolders", AutoSize = true, Checked = string.IsNullOrEmpty(initialPattern) || initialPattern.Contains("\\**\\") };
            Recursive.CheckedChanged += Recursive_CheckedChanged;
            var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
            var ok = new Button { Text = "OK", Image = GlobalInstances.ApplyBtnIcon, ImageAlign = ContentAlignment.MiddleLeft, TextAlign = ContentAlignment.MiddleRight, Size = new Size(90, 30) };
            var cancel = new Button { Text = "Cancel", Image = GlobalInstances.CancelBtnIcon, ImageAlign = ContentAlignment.MiddleLeft, TextAlign = ContentAlignment.MiddleRight, DialogResult = DialogResult.Cancel, Size = new Size(90, 30) };
            ok.Click += (sender, args) =>
            {
                try
                {
                    var parsed = new ExecutablePathPattern(PatternBox.Text);
                    PatternBox.Text = parsed.Pattern;
                    DialogResult = DialogResult.OK;
                }
                catch (ArgumentException e) { MessageBox.Show(this, e.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            };
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(PatternBox, 0, 0);
            layout.Controls.Add(browse, 1, 0);
            layout.Controls.Add(Recursive, 0, 1);
            layout.SetColumnSpan(Recursive, 2);
            layout.Controls.Add(buttons, 0, 2);
            layout.SetColumnSpan(buttons, 2);
            Controls.Add(layout);
            AcceptButton = ok;
            CancelButton = cancel;
        }

        private void Browse_Click(object sender, EventArgs args)
        {
            string? initialFolder = null;
            try { initialFolder = new ExecutablePathPattern(PatternBox.Text).RootPath; }
            catch (ArgumentException) { }
            try
            {
                string? folder = ModernFolderPicker.SelectFolder(this, initialFolder);
                if (folder != null)
                    PatternBox.Text = CreateFolderPattern(folder, Recursive.Checked);
            }
            catch (Exception error) when (error is COMException || error is ArgumentException)
            {
                MessageBox.Show(this, error.Message, Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private static string CreateFolderPattern(string folder, bool recursive)
        {
            return new ExecutablePathPattern(folder.TrimEnd('\\') + (recursive ? "\\**\\*.exe" : "\\*.exe")).Pattern;
        }

        private void Recursive_CheckedChanged(object sender, EventArgs args)
        {
            string path = PatternBox.Text;
            int separator = path.LastIndexOf('\\');
            if (separator < 0) return;
            if (Recursive.Checked && !path.Contains("\\**\\"))
                PatternBox.Text = path.Insert(separator + 1, "**\\");
            else if (!Recursive.Checked)
                PatternBox.Text = path.Replace("\\**\\", "\\");
        }
    }

    internal static class ModernFolderPicker
    {
        private const uint PickFolders = 0x20;
        private const uint ForceFileSystem = 0x40;
        private const uint PathMustExist = 0x800;
        private const uint DontAddToRecent = 0x02000000;
        private const uint FileSystemPath = 0x80058000;
        private const int Cancelled = unchecked((int)0x800704C7);

        internal static string? SelectFolder(IWin32Window owner, string? initialFolder)
        {
            IFileDialog dialog = CreateDialog(initialFolder);
            IShellItem? selected = null;
            IntPtr name = IntPtr.Zero;
            try
            {
                int result = dialog.Show(owner.Handle);
                if (result == Cancelled) return null;
                Marshal.ThrowExceptionForHR(result);
                dialog.GetResult(out selected);
                selected.GetDisplayName(FileSystemPath, out name);
                return Marshal.PtrToStringUni(name);
            }
            finally
            {
                if (name != IntPtr.Zero) Marshal.FreeCoTaskMem(name);
                if (selected != null) Marshal.ReleaseComObject(selected);
                Marshal.ReleaseComObject(dialog);
            }
        }

        private static IFileDialog CreateDialog(string? initialFolder)
        {
            var dialog = (IFileDialog)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7")))!;
            try
            {
                dialog.GetOptions(out uint options);
                dialog.SetOptions(options | PickFolders | ForceFileSystem | PathMustExist | DontAddToRecent);
                dialog.SetTitle("Select executable folder");
                if (initialFolder != null && initialFolder.Length != 0 && Directory.Exists(initialFolder))
                {
                    Guid iid = typeof(IShellItem).GUID;
                    SHCreateItemFromParsingName(initialFolder, IntPtr.Zero, ref iid, out IShellItem folder);
                    try { dialog.SetFolder(folder); }
                    finally { Marshal.ReleaseComObject(folder); }
                }
                return dialog;
            }
            catch
            {
                Marshal.ReleaseComObject(dialog);
                throw;
            }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, PreserveSig = false)]
        private static extern void SHCreateItemFromParsingName(string path, IntPtr bindingContext, ref Guid interfaceId,
            [MarshalAs(UnmanagedType.Interface)] out IShellItem item);

        // Declaration order follows the native IModalWindow/IFileDialog vtable.
        [ComImport, Guid("42F85136-DB7E-439C-85F1-E4075D135FC8"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IFileDialog
        {
            [PreserveSig] int Show(IntPtr owner);
            void SetFileTypes(uint count, IntPtr types);
            void SetFileTypeIndex(uint index);
            void GetFileTypeIndex(out uint index);
            void Advise(IntPtr events, out uint cookie);
            void Unadvise(uint cookie);
            void SetOptions(uint options);
            void GetOptions(out uint options);
            void SetDefaultFolder(IShellItem folder);
            void SetFolder(IShellItem folder);
            void GetFolder(out IShellItem folder);
            void GetCurrentSelection(out IShellItem item);
            void SetFileName([MarshalAs(UnmanagedType.LPWStr)] string name);
            void GetFileName(out IntPtr name);
            void SetTitle([MarshalAs(UnmanagedType.LPWStr)] string title);
            void SetOkButtonLabel([MarshalAs(UnmanagedType.LPWStr)] string text);
            void SetFileNameLabel([MarshalAs(UnmanagedType.LPWStr)] string label);
            void GetResult(out IShellItem item);
            void AddPlace(IShellItem item, uint placement);
            void SetDefaultExtension([MarshalAs(UnmanagedType.LPWStr)] string extension);
            void Close(int result);
            void SetClientGuid(ref Guid guid);
            void ClearClientData();
            void SetFilter(IntPtr filter);
        }

        [ComImport, Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IShellItem
        {
            void BindToHandler(IntPtr bindingContext, ref Guid handler, ref Guid interfaceId, out IntPtr result);
            void GetParent(out IShellItem parent);
            void GetDisplayName(uint displayNameType, out IntPtr name);
            void GetAttributes(uint mask, out uint attributes);
            void Compare(IShellItem item, uint hint, out int order);
        }
    }
}
