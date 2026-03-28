/* ==================== NOTES FEATURE ==================== */
/* Personal notes for courses and challenges */

// ============== LocalStorage ==============
const NOTES_KEY = 'study_hub_notes';

function getAllNotes() {
    try {
        return JSON.parse(localStorage.getItem(NOTES_KEY) || '[]');
    } catch { return []; }
}

function saveAllNotes(notes) {
    localStorage.setItem(NOTES_KEY, JSON.stringify(notes));
}

function addNote(note) {
    const notes = getAllNotes();
    const newNote = {
        id: 'note-' + Date.now(),
        title: note.title || 'Untitled',
        content: note.content || '',
        context: note.context || 'general', // video, ctf, course
        contextId: note.contextId || null,
        contextTitle: note.contextTitle || '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };
    notes.unshift(newNote);
    saveAllNotes(notes);
    return newNote;
}

function updateNote(noteId, updates) {
    const notes = getAllNotes();
    const index = notes.findIndex(n => n.id === noteId);
    if (index !== -1) {
        notes[index] = { ...notes[index], ...updates, updatedAt: new Date().toISOString() };
        saveAllNotes(notes);
        return notes[index];
    }
    return null;
}

function deleteNote(noteId) {
    const notes = getAllNotes();
    const filtered = notes.filter(n => n.id !== noteId);
    saveAllNotes(filtered);
    return true;
}

function getNotesForContext(contextId) {
    return getAllNotes().filter(n => n.contextId === contextId);
}

// ============== Note Modal ==============
function showNoteModal(context = 'general', contextId = null, contextTitle = '') {
    // Check if modal already exists
    let modal = document.getElementById('note-modal');
    if (!modal) {
        modal = document.createElement('div');
        modal.id = 'note-modal';
        document.body.appendChild(modal);
    }

    // Get existing note for this context
    const existingNotes = contextId ? getNotesForContext(contextId) : [];
    const existingNote = existingNotes[0] || null;

    modal.innerHTML = `
        <style>
            #note-modal {
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: rgba(0,0,0,0.8);
                backdrop-filter: blur(10px);
                z-index: 99999;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: fadeIn 0.2s ease;
            }
            .note-modal-content {
                background: #1a1a2e;
                border-radius: 20px;
                width: 90%;
                max-width: 600px;
                padding: 30px;
                border: 1px solid rgba(255,255,255,0.1);
                box-shadow: 0 30px 60px rgba(0,0,0,0.5);
            }
            .note-modal-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }
            .note-modal-title {
                color: white;
                font-size: 1.3rem;
                font-weight: 700;
            }
            .note-close-btn {
                background: none;
                border: none;
                color: #888;
                font-size: 1.5rem;
                cursor: pointer;
            }
            .note-context-badge {
                background: rgba(220,53,69,0.15);
                color: #dc3545;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.8rem;
                margin-bottom: 15px;
                display: inline-block;
            }
            .note-input {
                width: 100%;
                background: rgba(255,255,255,0.05);
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 10px;
                padding: 12px 16px;
                color: white;
                font-size: 1rem;
                margin-bottom: 15px;
            }
            .note-input:focus {
                outline: none;
                border-color: #dc3545;
            }
            .note-textarea {
                min-height: 200px;
                resize: vertical;
                font-family: inherit;
            }
            .note-actions {
                display: flex;
                gap: 10px;
                justify-content: flex-end;
                margin-top: 20px;
            }
            .note-btn {
                padding: 10px 24px;
                border-radius: 10px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s;
            }
            .note-btn-primary {
                background: linear-gradient(135deg, #dc3545, #c82333);
                border: none;
                color: white;
            }
            .note-btn-secondary {
                background: rgba(255,255,255,0.1);
                border: 1px solid rgba(255,255,255,0.2);
                color: white;
            }
            @keyframes fadeIn {
                from { opacity: 0; }
                to { opacity: 1; }
            }
        </style>
        
        <div class="note-modal-content">
            <div class="note-modal-header">
                <span class="note-modal-title"><i class="fas fa-sticky-note me-2"></i>${existingNote ? 'Edit Note' : 'Add Note'}</span>
                <button class="note-close-btn" onclick="closeNoteModal()"><i class="fas fa-times"></i></button>
            </div>
            
            ${contextTitle ? `<div class="note-context-badge"><i class="fas fa-link me-1"></i>${contextTitle}</div>` : ''}
            
            <input type="text" class="note-input" id="note-title-input" placeholder="Note title..." 
                   value="${existingNote ? existingNote.title : ''}">
            
            <textarea class="note-input note-textarea" id="note-content-input" 
                      placeholder="Write your notes here...">${existingNote ? existingNote.content : ''}</textarea>
            
            <div class="note-actions">
                ${existingNote ? `
                    <button class="note-btn note-btn-secondary" onclick="deleteNoteAndClose('${existingNote.id}')">
                        <i class="fas fa-trash me-1"></i> Delete
                    </button>
                ` : ''}
                <button class="note-btn note-btn-secondary" onclick="closeNoteModal()">Cancel</button>
                <button class="note-btn note-btn-primary" onclick="saveNoteFromModal('${context}', '${contextId || ''}', '${contextTitle}', '${existingNote ? existingNote.id : ''}')">
                    <i class="fas fa-save me-1"></i> Save
                </button>
            </div>
        </div>
    `;

    modal.style.display = 'flex';
}

function closeNoteModal() {
    const modal = document.getElementById('note-modal');
    if (modal) modal.style.display = 'none';
}

function saveNoteFromModal(context, contextId, contextTitle, existingId) {
    const title = document.getElementById('note-title-input').value.trim();
    const content = document.getElementById('note-content-input').value.trim();

    if (!title && !content) {
        alert('Please add a title or content');
        return;
    }

    if (existingId) {
        updateNote(existingId, { title, content });
    } else {
        addNote({
            title: title || 'Untitled Note',
            content,
            context,
            contextId: contextId || null,
            contextTitle: contextTitle || ''
        });
    }

    closeNoteModal();

    // Refresh notes page if on it
    if (window.location.hash.includes('notes')) {
        loadPage('notes');
    }
}

function deleteNoteAndClose(noteId) {
    if (confirm('Delete this note?')) {
        deleteNote(noteId);
        closeNoteModal();
        if (window.location.hash.includes('notes')) {
            loadPage('notes');
        }
    }
}

// ============== Notes Page ==============
function pageNotes() {
    const notes = getAllNotes();

    const contextIcons = {
        video: '<i class="fas fa-play-circle text-danger"></i>',
        ctf: '<i class="fas fa-flag text-warning"></i>',
        course: '<i class="fas fa-book text-info"></i>',
        general: '<i class="fas fa-sticky-note text-secondary"></i>'
    };

    return `
    <style>
        .notes-page {
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 100%);
            min-height: 100vh;
            padding: 30px;
        }
        .notes-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        .notes-title {
            font-size: 2rem;
            font-weight: 700;
            color: white;
        }
        .notes-add-btn {
            background: linear-gradient(135deg, #dc3545, #c82333);
            border: none;
            padding: 12px 24px;
            border-radius: 12px;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }
        .notes-add-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(220,53,69,0.3);
        }
        .notes-search {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.1);
            border-radius: 12px;
            padding: 12px 20px;
            color: white;
            width: 100%;
            max-width: 400px;
            margin-bottom: 30px;
        }
        .notes-search:focus {
            outline: none;
            border-color: #dc3545;
        }
        .notes-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
        }
        .note-card {
            background: rgba(255,255,255,0.03);
            border-radius: 16px;
            padding: 20px;
            border: 1px solid rgba(255,255,255,0.1);
            cursor: pointer;
            transition: all 0.3s;
        }
        .note-card:hover {
            transform: translateY(-5px);
            border-color: rgba(220,53,69,0.3);
        }
        .note-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }
        .note-card-title {
            color: white;
            font-weight: 600;
            font-size: 1.1rem;
        }
        .note-card-context {
            font-size: 0.8rem;
            color: #888;
        }
        .note-card-content {
            color: #aaa;
            font-size: 0.9rem;
            line-height: 1.5;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }
        .note-card-footer {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255,255,255,0.05);
            font-size: 0.75rem;
            color: #666;
        }
        .notes-empty {
            text-align: center;
            padding: 60px 20px;
        }
        .notes-empty-icon {
            font-size: 4rem;
            color: #333;
            margin-bottom: 20px;
        }
    </style>

    <div class="notes-page">
        <div class="notes-header">
            <h1 class="notes-title"><i class="fas fa-sticky-note me-2"></i>My Notes</h1>
            <button class="notes-add-btn" onclick="showNoteModal()">
                <i class="fas fa-plus me-2"></i>New Note
            </button>
        </div>
        
        <input type="text" class="notes-search" placeholder="Search notes..." 
               onkeyup="filterNotes(this.value)">
        
        ${notes.length === 0 ? `
            <div class="notes-empty">
                <div class="notes-empty-icon"><i class="fas fa-sticky-note"></i></div>
                <h3 class="text-white mb-2">No Notes Yet</h3>
                <p class="text-muted">Create your first note to get started</p>
                <button class="notes-add-btn mt-3" onclick="showNoteModal()">
                    <i class="fas fa-plus me-2"></i>Create Note
                </button>
            </div>
        ` : `
            <div class="notes-grid" id="notes-grid">
                ${notes.map(note => `
                    <div class="note-card" onclick="showNoteModal('${note.context}', '${note.contextId || ''}', '${note.contextTitle || ''}')">
                        <div class="note-card-header">
                            <span class="note-card-title">${note.title}</span>
                            <span class="note-card-context">${contextIcons[note.context] || contextIcons.general}</span>
                        </div>
                        ${note.contextTitle ? `<div class="note-card-context mb-2">${note.contextTitle}</div>` : ''}
                        <div class="note-card-content">${note.content || '<em>No content</em>'}</div>
                        <div class="note-card-footer">
                            <i class="fas fa-clock me-1"></i>${new Date(note.updatedAt).toLocaleDateString()}
                        </div>
                    </div>
                `).join('')}
            </div>
        `}
    </div>
    `;
}

function filterNotes(query) {
    const notes = getAllNotes();
    const filtered = notes.filter(n =>
        n.title.toLowerCase().includes(query.toLowerCase()) ||
        n.content.toLowerCase().includes(query.toLowerCase())
    );

    const grid = document.getElementById('notes-grid');
    if (!grid) return;

    const contextIcons = {
        video: '<i class="fas fa-play-circle text-danger"></i>',
        ctf: '<i class="fas fa-flag text-warning"></i>',
        course: '<i class="fas fa-book text-info"></i>',
        general: '<i class="fas fa-sticky-note text-secondary"></i>'
    };

    grid.innerHTML = filtered.map(note => `
        <div class="note-card" onclick="showNoteModal('${note.context}', '${note.contextId || ''}', '${note.contextTitle || ''}')">
            <div class="note-card-header">
                <span class="note-card-title">${note.title}</span>
                <span class="note-card-context">${contextIcons[note.context] || contextIcons.general}</span>
            </div>
            ${note.contextTitle ? `<div class="note-card-context mb-2">${note.contextTitle}</div>` : ''}
            <div class="note-card-content">${note.content || '<em>No content</em>'}</div>
            <div class="note-card-footer">
                <i class="fas fa-clock me-1"></i>${new Date(note.updatedAt).toLocaleDateString()}
            </div>
        </div>
    `).join('');
}

// ============== Exports ==============
window.pageNotes = pageNotes;
window.showNoteModal = showNoteModal;
window.closeNoteModal = closeNoteModal;
window.saveNoteFromModal = saveNoteFromModal;
window.deleteNoteAndClose = deleteNoteAndClose;
window.filterNotes = filterNotes;
window.getAllNotes = getAllNotes;
window.addNote = addNote;
window.getNotesForContext = getNotesForContext;

function initNotes() {
    console.log('Notes system initialized');
}
window.initNotes = initNotes;
