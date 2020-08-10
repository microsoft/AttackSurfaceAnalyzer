// Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT License.
using Serilog;
using System;
using System.Collections.Generic;
using System.IO;

namespace Microsoft.CST.AttackSurfaceAnalyzer.Utils
{
    public class FileWatcher : IDisposable
    {
        // Default constructor which gathers everything and prints to stdout.
        public FileWatcher() : this("/")
        {
        }

        // 'Choose your directory to stdout' constructor
        public FileWatcher(String DirectoryName) : this(DirectoryName, DefaultChangedDelegate, DefaultChangedDelegate, DefaultChangedDelegate, DefaultRenamedDelegate)
        {
        }

        // 'Normal' Constructor
        public FileWatcher(String DirectoryName, Action<EventArgs> OnChangedAction, Action<EventArgs> OnCreatedAction, Action<EventArgs> OnDeletedAction, Action<EventArgs> OnRenamedAction) : this(DirectoryName, OnChangedAction, OnCreatedAction, OnDeletedAction, OnRenamedAction, DefaultFilters, DefaultIncludeSubdirectories)
        {
        }

        // 'About as detailed as possible' Constructor
        public FileWatcher(String DirectoryName, Action<EventArgs> OnChangedAction, Action<EventArgs> OnCreatedAction, Action<EventArgs> OnDeletedAction, Action<EventArgs> OnRenamedAction, NotifyFilters NotifyFilters, bool IncludeSubdirectories)
        {
            EventList = new List<EventArgs>();
            OnChangedDelegate = OnChangedAction;
            OnCreatedDelegate = OnCreatedAction;
            OnDeletedDelegate = OnDeletedAction;
            OnRenamedDelegate = OnRenamedAction;

            watcher = new FileSystemWatcher();

            watcher.BeginInit();

            watcher.Path = DirectoryName;
            watcher.NotifyFilter = NotifyFilters;

            watcher.IncludeSubdirectories = IncludeSubdirectories;
            watcher.Changed += new FileSystemEventHandler(OnChanged);
            watcher.Created += new FileSystemEventHandler(OnChanged);
            watcher.Deleted += new FileSystemEventHandler(OnChanged);
            watcher.Renamed += new RenamedEventHandler(OnRenamed);

            watcher.EndInit();
        }

        public List<EventArgs> EventList { get; }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public bool IsRunning()
        {
            return watcher.EnableRaisingEvents;
        }

        public void Start()
        {
            watcher.EnableRaisingEvents = true;
        }

        public void Stop()
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                watcher.Dispose();
            }
        }

        private const NotifyFilters DefaultFilters = NotifyFilters.Attributes
                                                                                                                                | NotifyFilters.CreationTime
                                                | NotifyFilters.DirectoryName
                                                | NotifyFilters.FileName
                                                | NotifyFilters.LastAccess
                                                | NotifyFilters.LastWrite
                                                | NotifyFilters.Security
                                                | NotifyFilters.Size;

        private const bool DefaultIncludeSubdirectories = true;
        private static readonly Action<EventArgs> DefaultChangedDelegate = (e) => { FileSystemEventArgs i_e = (FileSystemEventArgs)e; Log.Information(i_e.ChangeType.ToString() + " " + i_e.FullPath); };
        private static readonly Action<EventArgs> DefaultRenamedDelegate = (e) => { RenamedEventArgs i_e = (RenamedEventArgs)e; Log.Information(i_e.ChangeType.ToString() + " " + i_e.OldFullPath + " " + i_e.FullPath); };
        private readonly Action<EventArgs> OnChangedDelegate;
        private readonly Action<EventArgs> OnCreatedDelegate;
        private readonly Action<EventArgs> OnDeletedDelegate;
        private readonly Action<EventArgs> OnRenamedDelegate;
        private readonly FileSystemWatcher watcher;

        private void OnChanged(object source, FileSystemEventArgs e)
        {
            EventList.Add(e);
            OnChangedDelegate(e);
        }

        private void OnCreated(object source, FileSystemEventArgs e)
        {
            EventList.Add(e);
            OnCreatedDelegate(e);
        }

        private void OnDeleted(object source, FileSystemEventArgs e)
        {
            EventList.Add(e);
            OnDeletedDelegate(e);
        }

        private void OnRenamed(object source, FileSystemEventArgs e)
        {
            EventList.Add(e);
            OnRenamedDelegate(e);
        }
    }
}