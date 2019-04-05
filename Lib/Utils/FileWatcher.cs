// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System;
using System.Collections.Generic;
using System.IO;
using Serilog;


namespace AttackSurfaceAnalyzer.Utils
{
    public class FileWatcher
    {
        private FileSystemWatcher watcher;

        public readonly List<EventArgs> EventList = new List<EventArgs>();

        private static readonly Action<EventArgs> DefaultChangedDelegate = (e) => { FileSystemEventArgs i_e = (FileSystemEventArgs)e; Log.Information(i_e.ChangeType.ToString() + " " + i_e.FullPath.ToString()); };
        private static readonly Action<EventArgs> DefaultRenamedDelegate = (e) => { RenamedEventArgs i_e = (RenamedEventArgs)e; Log.Information(i_e.ChangeType.ToString() + " " + i_e.OldFullPath.ToString() + " " + i_e.FullPath.ToString()); };

        private static readonly NotifyFilters DefaultFilters = NotifyFilters.Attributes
                                                | NotifyFilters.CreationTime
                                                | NotifyFilters.DirectoryName
                                                | NotifyFilters.FileName
                                                | NotifyFilters.LastAccess
                                                | NotifyFilters.LastWrite
                                                | NotifyFilters.Security
                                                | NotifyFilters.Size;

        private static readonly bool DefaultIncludeSubdirectories = true;


        private Action<EventArgs> OnChangedDelegate;
        private Action<EventArgs> OnCreatedDelegate;
        private Action<EventArgs> OnDeletedDelegate;
        private Action<EventArgs> OnRenamedDelegate;

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

            OnChangedDelegate = OnChangedAction;
            OnCreatedDelegate = OnCreatedAction;
            OnDeletedDelegate = OnDeletedAction;
            OnRenamedDelegate = OnDeletedAction;

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