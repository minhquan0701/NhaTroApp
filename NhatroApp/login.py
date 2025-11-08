import tkinter as tk
from tkinter import messagebox
import sqlite3
import re  # Đảm bảo thêm dòng này ở đầu file (ngay sau import sqlite3)
from datetime import datetime
import hashlib
# =========================
# HÀM KIỂM TRA MẬT KHẨU MẠNH
# =========================
def validate_password(pw):
    if len(pw) < 8:
        return "Mật khẩu phải có ít nhất 8 ký tự!"
    if not re.search(r"[A-Z]", pw):
        return "Mật khẩu phải chứa ít nhất 1 chữ in hoa!"
    if not re.search(r"[a-z]", pw):
        return "Mật khẩu phải chứa ít nhất 1 chữ thường!"
    if not re.search(r"[0-9]", pw):
        return "Mật khẩu phải chứa ít nhất 1 chữ số!"
    return None  # hợp lệ

def register_user(vaitro, title):
    reg_window = tk.Toplevel(root)
    reg_window.title(title)
    reg_window.geometry("400x550")
    reg_window.config(bg="#f9f9f9")

    tk.Label(reg_window, text=title, font=("Arial", 14, "bold"), bg="#f9f9f9").pack(pady=15)

    # Các trường dữ liệu
    fields = {}
    labels = [
        ("Họ và tên:", "HoTen"),
        ("Ngày sinh (dd/mm/yyyy):", "NgaySinh"),
        ("Email (Gmail):", "Email"),
        ("Số điện thoại:", "SDT"),
        ("CCCD/CMND:", "CCCD"),
        ("Tên đăng nhập:", "Username"),
        ("Mật khẩu:", "Password"),
        ("Nhập lại mật khẩu:", "Confirm")
    ]

    for label, key in labels:
        tk.Label(reg_window, text=label, bg="#f9f9f9").pack()
        entry = tk.Entry(reg_window, width=35, show="*" if "Mật khẩu" in label else "")
        entry.pack(pady=4)
        fields[key] = entry

    def do_register():
        data = {k: v.get().strip() for k, v in fields.items()}

        # --- 1. Kiểm tra trường bắt buộc ---
        if not all([data["HoTen"], data["Username"], data["Password"], data["Confirm"], data["SDT"], data["Email"]]):
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đủ các trường bắt buộc.")
            return

        # --- 2. Kiểm tra mật khẩu khớp ---
        if data["Password"] != data["Confirm"]:
            messagebox.showerror("Lỗi", "Mật khẩu nhập lại không khớp.")
            return

        # --- 3. Kiểm tra họ tên ---
        if not re.match(r"^[A-Za-zÀ-ỹ\s]+$", data["HoTen"]):
            messagebox.showerror("Lỗi", "Họ tên chỉ được chứa chữ cái và khoảng trắng.")
            return

        # --- 4. Kiểm tra ngày sinh ---
        if data["NgaySinh"]:
            parsed = None
            for fmt in ("%d/%m/%Y", "%-d/%-m/%Y", "%d-%m-%Y", "%Y-%m-%d"):
                try:
                    parsed = datetime.strptime(data["NgaySinh"], fmt)
                    break
                except Exception:
                    continue

    # Windows' strptime doesn't support %-d/%-m, so try manual fix:
            if parsed is None:
        # try to normalize single-digit day/month to two-digit form
                parts = data["NgaySinh"].replace("-", "/").split("/")
                if len(parts) == 3 and all(part.isdigit() for part in parts):
                    d, m, y = parts
                    d = d.zfill(2)
                    m = m.zfill(2)
                    try:
                        parsed = datetime.strptime(f"{d}/{m}/{y}", "%d/%m/%Y")
                    except Exception:
                        parsed = None

            if parsed is None:
                messagebox.showerror("Lỗi", "Ngày sinh không hợp lệ! Định dạng dd/mm/yyyy.")
                return

        # --- 5. Kiểm tra email Gmail ---
        if not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", data["Email"]):
            messagebox.showerror("Lỗi", "Email không hợp lệ! Vui lòng nhập địa chỉ Gmail đúng định dạng (vd: ten@gmail.com).")
            return

        # --- 6. Kiểm tra số điện thoại ---
        if not re.match(r"^(0[0-9]{9})$", data["SDT"]):
            messagebox.showerror("Lỗi", "Số điện thoại không hợp lệ! Phải gồm 10 chữ số và bắt đầu bằng 0.")
            return

        # --- 7. Kiểm tra CCCD ---
        if data["CCCD"]:
            if not re.match(r"^\d{9}$", data["CCCD"]) and not re.match(r"^\d{12}$", data["CCCD"]):
                messagebox.showerror("Lỗi", "CCCD/CMND phải gồm 9 hoặc 12 chữ số.")
                return

        # --- 8. Kiểm tra tên đăng nhập ---
        if len(data["Username"]) < 4 or " " in data["Username"]:
            messagebox.showerror("Lỗi", "Tên đăng nhập phải có ít nhất 4 ký tự và không chứa khoảng trắng.")
            return

        # --- 9. Kiểm tra mật khẩu mạnh ---
        pw_error = validate_password(data["Password"])
        if pw_error:
            messagebox.showerror("Lỗi", pw_error)
            return

        # --- 10. Lưu dữ liệu vào database ---
        conn = sqlite3.connect("nhatro.db")
        c = conn.cursor()
        try:
            # Mã hóa mật khẩu trước khi lưu
            hashed_pw = hashlib.sha256(data["Password"].encode()).hexdigest()

            c.execute("""
                INSERT INTO User (Username, Password, VaiTro, HoTen, NgaySinh, Email, SDT, CCCD)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (data["Username"], hashed_pw, vaitro, data["HoTen"], data["NgaySinh"],
      data["Email"], data["SDT"], data["CCCD"]))

            conn.commit()
            role_text = "Chủ trọ" if vaitro == 1 else "Người thuê"
            messagebox.showinfo("Thành công", f"Đăng ký {role_text} thành công!")
            reg_window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Lỗi", "Tên đăng nhập đã tồn tại.")
        finally:
            conn.close()

    tk.Button(reg_window, text="Đăng ký", bg="#4CAF50", fg="white",
              font=("Arial", 11, "bold"), width=15, command=do_register).pack(pady=15)


# =========================
# KHỞI TẠO DATABASE
# =========================
def init_db():
    conn = sqlite3.connect("nhatro.db")
    c = conn.cursor()

    # --- BẢNG NGƯỜI DÙNG ---
    c.execute("""
        CREATE TABLE IF NOT EXISTS User (
            User_ID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT UNIQUE,
            Password TEXT,
            VaiTro INTEGER,
            HoTen TEXT,
            NgaySinh TEXT,
            Email TEXT,
            SDT TEXT,
            CCCD TEXT
        )
    """)

    conn.commit()
    conn.close()

init_db()

# =========================
# HÀM ĐĂNG NHẬP CHỦ TRỌ
# =========================
def open_owner_login():
    login_window = tk.Toplevel(root)
    login_window.title("Đăng nhập - Chủ trọ")
    login_window.geometry("350x320")
    login_window.config(bg="#f9f9f9")

    tk.Label(login_window, text="Đăng nhập dành cho Chủ trọ", 
             font=("Arial", 14, "bold"), bg="#f9f9f9").pack(pady=20)

    tk.Label(login_window, text="Tên đăng nhập:", bg="#f9f9f9").pack()
    username_entry = tk.Entry(login_window, width=30)
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Mật khẩu:", bg="#f9f9f9").pack()
    password_entry = tk.Entry(login_window, width=30, show="*")
    password_entry.pack(pady=5)
# Thêm checkbox để hiển thị mật khẩu
    def toggle_password():
        if show_password_var.get():
            password_entry.config(show="")
        else:
            password_entry.config(show="*")
    show_password_var = tk.BooleanVar()
    show_password_checkbox = tk.Checkbutton(login_window, text="Hiện mật khẩu", variable=show_password_var, bg="#f9f9f9", command=toggle_password)
    show_password_checkbox.pack()


    def login():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        conn = sqlite3.connect("nhatro.db")
        c = conn.cursor()
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT * FROM User WHERE Username=? AND Password=? AND VaiTro=1", (username, hashed_pw))

        user = c.fetchone()
        conn.close()
        if user:
            messagebox.showinfo("Đăng nhập thành công", f"Chào mừng, Chủ trọ {user[4]}!")
            login_window.destroy()
            open_owner_dashboard(user[0], user[4])
        else:
            messagebox.showerror("Lỗi", "Tên đăng nhập hoặc mật khẩu sai!")

    def forgot_password():
        forgot_window = tk.Toplevel(login_window)
        forgot_window.title("Quên mật khẩu - Chủ trọ")
        forgot_window.geometry("350x250")
        forgot_window.config(bg="#f9f9f9")

        tk.Label(forgot_window, text="Nhập thông tin để đặt lại mật khẩu",
                font=("Arial", 12, "bold"), bg="#f9f9f9").pack(pady=15)

        tk.Label(forgot_window, text="Tên đăng nhập:", bg="#f9f9f9").pack()
        f_username = tk.Entry(forgot_window, width=30)
        f_username.pack(pady=5)

        tk.Label(forgot_window, text="Số điện thoại đã đăng ký:", bg="#f9f9f9").pack()
        f_phone = tk.Entry(forgot_window, width=30)
        f_phone.pack(pady=5)

        def verify_user():
            u = f_username.get().strip()
            phone = f_phone.get().strip()
            conn = sqlite3.connect("nhatro.db")
            c = conn.cursor()
            c.execute("SELECT * FROM User WHERE Username=? AND SDT=? AND VaiTro=1", (u, phone))
            user = c.fetchone()
            conn.close()

            if user:
                reset_window = tk.Toplevel(forgot_window)
                reset_window.title("Đặt lại mật khẩu")
                reset_window.geometry("300x200")
                reset_window.config(bg="#f9f9f9")

                tk.Label(reset_window, text="Mật khẩu mới:", bg="#f9f9f9").pack(pady=5)
                new_pw = tk.Entry(reset_window, width=30, show="*")
                new_pw.pack(pady=5)

                tk.Label(reset_window, text="Xác nhận mật khẩu:", bg="#f9f9f9").pack(pady=5)
                confirm_pw = tk.Entry(reset_window, width=30, show="*")
                confirm_pw.pack(pady=5)

                def reset_password():
                    if new_pw.get() != confirm_pw.get():
                        messagebox.showerror("Lỗi", "Mật khẩu xác nhận không khớp!")
                        return

                    pw_error = validate_password(new_pw.get())
                    if pw_error:
                        messagebox.showerror("Lỗi", pw_error)
                        return

                    hashed_pw = hashlib.sha256(new_pw.get().encode()).hexdigest()
                    conn = sqlite3.connect("nhatro.db")
                    c = conn.cursor()
                    c.execute("UPDATE User SET Password=? WHERE Username=?", (hashed_pw, u))
                    conn.commit()
                    conn.close()

                    messagebox.showinfo("Thành công", "Mật khẩu đã được đặt lại!")
                    reset_window.destroy()
                    forgot_window.destroy()

                tk.Button(reset_window, text="Xác nhận", bg="#4CAF50", fg="white",
                      font=("Arial", 11, "bold"), width=15, command=reset_password).pack(pady=10)
            else:
                messagebox.showerror("Lỗi", "Tên đăng nhập hoặc số điện thoại không đúng!")

        tk.Button(forgot_window, text="Xác nhận", bg="#4CAF50", fg="white",
                font=("Arial", 11, "bold"), width=15, command=verify_user).pack(pady=20)

    def register_owner():
        register_user(vaitro=1, title="Đăng ký Chủ trọ")

    tk.Button(login_window, text="Đăng nhập", font=("Arial", 11, "bold"),
              bg="#4CAF50", fg="white", width=15, command=login).pack(pady=10)
    tk.Button(login_window, text="Chưa có tài khoản? Đăng ký ngay", font=("Arial", 10, "underline"),
              bg="#f9f9f9", fg="blue", bd=0, cursor="hand2", command=register_owner).pack(pady=5)
    tk.Button(login_window, text="Quên mật khẩu?", font=("Arial", 10, "underline"),
              bg="#f9f9f9", fg="red", bd=0, cursor="hand2", command=forgot_password).pack(pady=5)

# =========================
# HÀM ĐĂNG NHẬP NGƯỜI THUÊ
# =========================
def open_tenant_page():
    login_window = tk.Toplevel(root)
    login_window.title("Đăng nhập - Người thuê")
    login_window.geometry("350x320")
    login_window.config(bg="#f9f9f9")

    tk.Label(login_window, text="Đăng nhập dành cho Người thuê", 
             font=("Arial", 14, "bold"), bg="#f9f9f9").pack(pady=20)

    tk.Label(login_window, text="Tên đăng nhập:", bg="#f9f9f9").pack()
    username_entry = tk.Entry(login_window, width=30)
    username_entry.pack(pady=5)

    tk.Label(login_window, text="Mật khẩu:", bg="#f9f9f9").pack()
    password_entry = tk.Entry(login_window, width=30, show="*")
    password_entry.pack(pady=5)
# 🆕 Thêm checkbox "Hiện mật khẩu"
    show_password_var = tk.BooleanVar()
    tk.Checkbutton(
        login_window,
        text="Hiện mật khẩu",
        variable=show_password_var,
        bg="#f9f9f9",
        command=lambda: password_entry.config(show="" if show_password_var.get() else "*")
    ).pack()

    # --- Xử lý đăng nhập ---
    def login():
        username = username_entry.get().strip()
        password = password_entry.get().strip()
        conn = sqlite3.connect("nhatro.db")
        c = conn.cursor()
        hashed_pw = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT * FROM User WHERE Username=? AND Password=? AND VaiTro=0", (username, hashed_pw))

        user = c.fetchone()
        conn.close()
        if user:
            messagebox.showinfo("Đăng nhập thành công", f"Chào mừng, {user[4]}!")
            login_window.destroy()
        else:
            messagebox.showerror("Lỗi", "Tên đăng nhập hoặc mật khẩu sai!")

    # --- Quên mật khẩu ---
    def forgot_password():
        forgot_window = tk.Toplevel(login_window)
        forgot_window.title("Quên mật khẩu - Người thuê")
        forgot_window.geometry("350x250")
        forgot_window.config(bg="#f9f9f9")

        tk.Label(forgot_window, text="Nhập thông tin để đặt lại mật khẩu",
                font=("Arial", 12, "bold"), bg="#f9f9f9").pack(pady=15)

        tk.Label(forgot_window, text="Tên đăng nhập:", bg="#f9f9f9").pack()
        f_username = tk.Entry(forgot_window, width=30)
        f_username.pack(pady=5)

        tk.Label(forgot_window, text="Số điện thoại đã đăng ký:", bg="#f9f9f9").pack()
        f_phone = tk.Entry(forgot_window, width=30)
        f_phone.pack(pady=5)

        def verify_user():
            u = f_username.get().strip()
            phone = f_phone.get().strip()
            conn = sqlite3.connect("nhatro.db")
            c = conn.cursor()
            c.execute("SELECT * FROM User WHERE Username=? AND SDT=? AND VaiTro=0", (u, phone))
            user = c.fetchone()
            conn.close()

            if user:
                reset_window = tk.Toplevel(forgot_window)
                reset_window.title("Đặt lại mật khẩu")
                reset_window.geometry("300x200")
                reset_window.config(bg="#f9f9f9")

                tk.Label(reset_window, text="Mật khẩu mới:", bg="#f9f9f9").pack(pady=5)
                new_pw = tk.Entry(reset_window, width=30, show="*")
                new_pw.pack(pady=5)

                tk.Label(reset_window, text="Xác nhận mật khẩu:", bg="#f9f9f9").pack(pady=5)
                confirm_pw = tk.Entry(reset_window, width=30, show="*")
                confirm_pw.pack(pady=5)

                def reset_password():
                    if new_pw.get() != confirm_pw.get():
                        messagebox.showerror("Lỗi", "Mật khẩu xác nhận không khớp!")
                        return
                    if len(new_pw.get()) < 6:
                        messagebox.showerror("Lỗi", "Mật khẩu phải có ít nhất 6 ký tự!")
                        return

                    hashed_pw = hashlib.sha256(new_pw.get().encode()).hexdigest()
                    conn = sqlite3.connect("nhatro.db")
                    c = conn.cursor()
                    c.execute("UPDATE User SET Password=? WHERE Username=?", (hashed_pw, u))
                    conn.commit()
                    conn.close()

                    messagebox.showinfo("Thành công", "Mật khẩu đã được đặt lại!")
                    reset_window.destroy()
                    forgot_window.destroy()

                tk.Button(reset_window, text="Xác nhận", bg="#4CAF50", fg="white",
                        font=("Arial", 11, "bold"), width=15, command=reset_password).pack(pady=10)
            else:
                messagebox.showerror("Lỗi", "Tên đăng nhập hoặc số điện thoại không đúng!")

        tk.Button(forgot_window, text="Xác nhận", bg="#4CAF50", fg="white",
                font=("Arial", 11, "bold"), width=15, command=verify_user).pack(pady=20)

    # --- Đăng ký tài khoản người thuê ---
    def register_tenant():
        register_user(vaitro=0, title="Đăng ký Người thuê")

    # --- Các nút chức năng chính ---
    tk.Button(login_window, text="Đăng nhập", font=("Arial", 11, "bold"),
              bg="#2196F3", fg="white", width=15, command=login).pack(pady=10)

    tk.Button(login_window, text="Chưa có tài khoản? Đăng ký ngay", font=("Arial", 10, "underline"),
              bg="#f9f9f9", fg="blue", bd=0, cursor="hand2", command=register_tenant).pack(pady=5)

    tk.Button(login_window, text="Quên mật khẩu?", font=("Arial", 10, "underline"),
              bg="#f9f9f9", fg="red", bd=0, cursor="hand2", command=forgot_password).pack(pady=5)

# =========================
# HÀM ĐĂNG KÝ
# =========================

    tk.Label(reg_window, text=title, font=("Arial", 14, "bold"), bg="#f9f9f9").pack(pady=15)

    fields = {}
    labels = [
        ("Họ và tên:", "HoTen"),
        ("Ngày sinh:", "NgaySinh"),
        ("Email:", "Email"),
        ("Số điện thoại:", "SDT"),
        ("CCCD/CMND:", "CCCD"),
        ("Tên đăng nhập:", "Username"),
        ("Mật khẩu:", "Password"),
        ("Nhập lại mật khẩu:", "Confirm")
    ]

    for label, key in labels:
        tk.Label(reg_window, text=label, bg="#f9f9f9").pack()
        entry = tk.Entry(reg_window, width=35, show="*" if "Mật khẩu" in label else "")
        entry.pack(pady=4)
        fields[key] = entry

    def do_register():
        data = {k: v.get().strip() for k, v in fields.items()}
        if not all([data["HoTen"], data["SDT"], data["Username"], data["Password"], data["Confirm"]]):
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập đủ các trường bắt buộc.")
            return
        if data["Password"] != data["Confirm"]:
            messagebox.showerror("Lỗi", "Mật khẩu nhập lại không khớp.")
            return
        conn = sqlite3.connect("nhatro.db")
        c = conn.cursor()
        try:
            c.execute("""
                INSERT INTO User (Username, Password, VaiTro, HoTen, NgaySinh, Email, SDT, CCCD)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (data["Username"], data["Password"], vaitro, data["HoTen"], data["NgaySinh"], data["Email"], data["SDT"], data["CCCD"]))
            conn.commit()
            role_text = "Chủ trọ" if vaitro == 1 else "Người thuê"
            messagebox.showinfo("Thành công", f"Đăng ký {role_text} thành công!")
            reg_window.destroy()
        except sqlite3.IntegrityError:
            messagebox.showerror("Lỗi", "Tên đăng nhập đã tồn tại.")
        finally:
            conn.close()

    tk.Button(reg_window, text="Đăng ký", bg="#4CAF50", fg="white", font=("Arial", 11, "bold"),
              width=15, command=do_register).pack(pady=15)

# =========================
# GIAO DIỆN SAU KHI ĐĂNG NHẬP
# =========================
def open_owner_dashboard(owner_id, owner_name):
    dashboard = tk.Toplevel(root)
    dashboard.title(f"Bảng điều khiển - Chủ trọ {owner_name}")
    dashboard.geometry("400x200")
    dashboard.config(bg="#f4f4f4")

    tk.Label(dashboard, text=f"Xin chào, Chủ trọ {owner_name}", 
             font=("Arial", 14, "bold"), bg="#f4f4f4").pack(pady=20)
    tk.Label(dashboard, text="(Chức năng quản lý sẽ được cập nhật sau)", 
             bg="#f4f4f4", fg="gray").pack()
    tk.Button(dashboard, text="Đăng xuất", width=15, bg="red", fg="white",
              font=("Arial", 11, "bold"), command=dashboard.destroy).pack(pady=20)

# =========================
# GIAO DIỆN CHÍNH
# =========================
root = tk.Tk()
root.title("Ứng dụng Quản lý Nhà trọ")
root.geometry("400x300")
root.config(bg="#f2f2f2")

tk.Label(root, text="Chào mừng đến với Ứng dụng Quản lý Nhà trọ", 
         font=("Arial", 14, "bold"), bg="#f2f2f2", wraplength=350, justify="center").pack(pady=30)

tk.Button(root, text="👑 Chủ trọ", font=("Arial", 12, "bold"),
          bg="#4CAF50", fg="white", width=15, height=2, command=open_owner_login).pack(pady=10)

tk.Button(root, text="🏠 Người thuê", font=("Arial", 12, "bold"),
          bg="#2196F3", fg="white", width=15, height=2, command=open_tenant_page).pack(pady=10)

tk.Label(root, text="© 2025 - Ứng dụng Quản lý Nhà trọ", 
         font=("Arial", 9), bg="#f2f2f2", fg="gray").pack(side="bottom", pady=10)

root.mainloop()


