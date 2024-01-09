import tkinter as tk
from tkinter import ttk

class CheatSheetApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Nmap Cheat Sheet")
        self.root.configure(bg='black')

        # Add a title label
        title_label = tk.Label(self.root, text="Nmap Cheat Sheet", font=('Arial', 16, 'bold'), fg='green', bg='black')
        title_label.pack(pady=10)

        # Create a frame to organize widgets
        frame = ttk.Frame(self.root, style="My.TFrame")
        frame.pack(fill='both', expand=True)

        # Create a Treeview widget on the left
        self.tree = ttk.Treeview(frame, style="My.Treeview")
        self.tree.heading('#0', text='Topics', anchor='w')
        self.tree.column('#0', width=150)
        self.tree.pack(side='left', fill='y', padx=10, pady=10, expand=True)

        # Create a Text widget on the right
        self.text = tk.Text(frame, wrap='word', width=40, height=10, font=('Arial', 12), fg='green', bg='black')
        self.text.pack(side='left', fill='both', expand=True, padx=10, pady=10)

        # Create a search bar
        self.search_var = tk.StringVar()
        search_bar = tk.Entry(frame, textvariable=self.search_var, fg='green', bg='black')
        search_bar.pack(side='top', fill='x', padx=10, pady=5)
        search_bar.bind('<KeyRelease>', self.filter_tree)

        # Create a copy button
        copy_button = tk.Button(frame, text="Copy Command", command=self.copy_command, fg='green', bg='black')
        copy_button.pack(side='top', pady=5)

        # Configure tags for treeview item colors
        self.tree.tag_configure('mytag', background='black', foreground='green')

        # Dictionary to store topic-command mappings
        self.topic_commands = {
            "all ports": "nmap -p- 192.168.1.1",
            "UDP port scan": "nmap 192.168.1.1 -sU",
            "TCP ACK port scan": "nmap 192.168.1.1 -sA"
        }

        # Add topics to the tree
        for i, (topic, command) in enumerate(self.topic_commands.items()):
            self.tree.insert('', 'end', text=topic, tags=('mytag',))

        # Bind the tree item selection to update the text widget
        self.tree.bind('<ButtonRelease-1>', lambda event: self.on_tree_select())

        # Define a custom ttk style for the frame
        ttk.Style().configure("My.TFrame", background='black')

        # Define a custom ttk style for the treeview
        ttk.Style().configure("My.Treeview",
                              background='black',
                              foreground='green',
                              fieldbackground='black',
                              highlightcolor='black',
                              highlightbackground='black',
                              borderwidth=0)

    def filter_tree(self, event):
        search_term = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())  # Clear the treeview
        for i, (topic, command) in enumerate(self.topic_commands.items()):
            if search_term in topic.lower():
                tags = ('mytag',)
                self.tree.insert('', 'end', text=topic, tags=tags)
        self.tree.bind('<ButtonRelease-1>', lambda event: self.on_tree_select())

    def copy_command(self):
        command_text = self.text.get('1.0', 'end-1c')  # Get command text without trailing newline
        self.root.clipboard_clear()
        self.root.clipboard_append(command_text)

    def on_tree_select(self):
        # Get the selected item in the tree
        selected_item = self.tree.selection()
        if selected_item:
            # Get the topic associated with the selected item
            topic = self.tree.item(selected_item, 'text')
            # Get the command associated with the selected topic from the dictionary
            command = self.topic_commands.get(topic, "")
            # Clear the text widget and insert the command
            self.text.delete('1.0', 'end')
            self.text.insert('1.0', command)

if __name__ == "__main__":
    root = tk.Tk()
    app = CheatSheetApp(root)
    root.mainloop()
